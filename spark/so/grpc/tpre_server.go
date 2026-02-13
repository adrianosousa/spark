package grpc

import (
	"context"
	"fmt"

	"github.com/lightsparkdev/spark/common/logging"
	pbfrost "github.com/lightsparkdev/spark/proto/frost"
	pbtpre "github.com/lightsparkdev/spark/proto/tpre"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/ent"
	"github.com/lightsparkdev/spark/so/helper"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TpreServer implements the TpreService gRPC server.
// It handles re-encryption requests from SDK clients and coordinates
// with peer operators to collect partial ECDH shares.
type TpreServer struct {
	pbtpre.UnimplementedTpreServiceServer
	config *so.Config
}

// NewTpreServer creates a new T-PRE gRPC server.
func NewTpreServer(config *so.Config) *TpreServer {
	return &TpreServer{config: config}
}

// RequestReEncryption handles a reader's request to re-encrypt a sealed content key.
//
// Flow:
// 1. Extract ephemeral public key from the ECIES ciphertext
// 2. Get partial ECDH shares from all operators (including self)
// 3. Send shares + ciphertext to the local FROST signer for threshold decryption
// 4. Re-encrypt the content key to the reader's public key
// 5. Return the re-encrypted key
func (s *TpreServer) RequestReEncryption(
	ctx context.Context,
	req *pbtpre.ReEncryptionRequest,
) (*pbtpre.ReEncryptionResponse, error) {
	logger := logging.GetLoggerFromContext(ctx)
	logger.Info("T-PRE: received re-encryption request",
		zap.String("transfer_id", req.TransferId),
		zap.Int("sealed_key_len", len(req.SealedContentKey)),
	)

	// Validate request
	if len(req.SealedContentKey) < 97 { // 65 (pubkey) + 16 (nonce) + 16 (tag)
		return nil, status.Error(codes.InvalidArgument, "sealed_content_key too short")
	}
	if len(req.ReaderPublicKey) != 33 && len(req.ReaderPublicKey) != 65 {
		return nil, status.Error(codes.InvalidArgument, "reader_public_key must be 33 or 65 bytes")
	}
	if len(req.PostId) == 0 {
		return nil, status.Error(codes.InvalidArgument, "post_id is required")
	}

	// TODO: Phase 3b — verify the Spark transfer (payment proof)
	// For the PoC, we skip payment verification and proceed directly.
	// In production:
	// 1. Look up transfer_id in the database
	// 2. Verify transfer.receiver == author_public_key
	// 3. Verify transfer.amount >= payment_amount_sats
	// 4. Verify transfer.status == COMPLETED
	logger.Info("T-PRE: skipping payment verification (PoC mode)")

	// Extract the 65-byte ephemeral public key from the ECIES ciphertext
	ephemeralPubKey := req.SealedContentKey[:65]

	// Step 1: Collect partial ECDH shares from all operators
	// Each operator asks its local FROST signer for a partial ECDH computation
	selection := helper.OperatorSelection{Option: helper.OperatorSelectionOptionAll}
	partialShares, err := helper.ExecuteTaskWithAllOperators(
		ctx, s.config, &selection,
		func(ctx context.Context, operator *so.SigningOperator) (*pbtpre.PartialEcdhShareResponse, error) {
			return s.getPartialEcdhFromOperator(ctx, operator, ephemeralPubKey)
		},
	)
	if err != nil {
		logger.Error("T-PRE: failed to collect partial ECDH shares", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "failed to collect ECDH shares: %v", err)
	}

	logger.Info("T-PRE: collected partial ECDH shares",
		zap.Int("count", len(partialShares)),
	)

	// Step 2: Send everything to local FROST signer for threshold decrypt + re-encrypt
	// The signer will:
	// a) Combine partial ECDH shares via Lagrange interpolation
	// b) Derive the AES key and decrypt the content key
	// c) Re-encrypt to the reader's public key

	// Collect shares as (operator_index, point) pairs for the Rust combiner
	// The operator index is derived from the operator identifier (1-based)
	type shareData struct {
		index uint32
		point []byte
	}
	shares := make([]shareData, 0, len(partialShares))
	for _, share := range partialShares {
		// Parse operator identifier to get 1-based index
		idx := s.operatorIdentifierToIndex(share.OperatorIdentifier)
		if idx == 0 {
			logger.Warn("T-PRE: unknown operator identifier", zap.String("id", share.OperatorIdentifier))
			continue
		}
		shares = append(shares, shareData{index: idx, point: share.PartialEcdhPoint})
	}

	if len(shares) < int(s.config.Threshold) {
		return nil, status.Errorf(codes.Internal,
			"insufficient ECDH shares: got %d, need %d", len(shares), s.config.Threshold)
	}

	// Use the FROST signer to do the heavy crypto work
	// We call a combined threshold-decrypt-and-reencrypt endpoint
	frostConn, err := s.config.NewFrostGRPCConnection()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to connect to FROST signer: %v", err)
	}
	defer frostConn.Close()

	frostClient := pbfrost.NewFrostServiceClient(frostConn)

	// Build the threshold_decrypt_reencrypt request
	// Convert our shares to the proto format
	protoShares := make([]*pbfrost.PartialEcdhShare, 0, len(shares))
	for _, share := range shares {
		protoShares = append(protoShares, &pbfrost.PartialEcdhShare{
			OperatorIndex:    share.index,
			PartialEcdhPoint: share.point,
		})
	}

	reencryptResp, err := frostClient.ThresholdDecryptReencrypt(ctx, &pbfrost.ThresholdDecryptReencryptRequest{
		SealedContentKey: req.SealedContentKey,
		ReaderPublicKey:  req.ReaderPublicKey,
		PartialShares:    protoShares,
		Threshold:        uint32(s.config.Threshold),
	})
	if err != nil {
		logger.Error("T-PRE: threshold decrypt+reencrypt failed", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "threshold decrypt+reencrypt failed: %v", err)
	}

	logger.Info("T-PRE: re-encryption flow complete",
		zap.Int("shares_collected", len(shares)),
		zap.String("transfer_id", req.TransferId),
	)

	return &pbtpre.ReEncryptionResponse{
		ReEncryptedKey: reencryptResp.ReEncryptedKey,
		PostId:         req.PostId,
		ContentKey:     reencryptResp.ContentKey,
	}, nil
}

// GetPartialEcdhShare handles internal operator-to-operator requests.
// A peer operator asks us to compute a partial ECDH using our FROST signer.
func (s *TpreServer) GetPartialEcdhShare(
	ctx context.Context,
	req *pbtpre.PartialEcdhShareRequest,
) (*pbtpre.PartialEcdhShareResponse, error) {
	logger := logging.GetLoggerFromContext(ctx)
	logger.Info("T-PRE: received partial ECDH share request",
		zap.String("request_id", req.RequestId),
	)

	// Connect to local FROST signer
	frostConn, err := s.config.NewFrostGRPCConnection()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to connect to FROST signer: %v", err)
	}
	defer frostConn.Close()

	frostClient := pbfrost.NewFrostServiceClient(frostConn)

	// Get the signing keyshare from the database
	keyPackage, err := s.getSigningKeyPackage(ctx, req.KeyshareId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get signing key package: %v", err)
	}

	// Call FROST signer's partial_ecdh RPC
	resp, err := frostClient.PartialEcdh(ctx, &pbfrost.PartialEcdhRequest{
		RequestId:          req.RequestId,
		EphemeralPublicKey: req.EphemeralPublicKey,
		KeyPackage:         keyPackage,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "FROST signer partial_ecdh failed: %v", err)
	}

	return &pbtpre.PartialEcdhShareResponse{
		PartialEcdhPoint:   resp.PartialEcdhPoint,
		OperatorIdentifier: string(s.config.Identifier),
	}, nil
}

// getPartialEcdhFromOperator requests a partial ECDH share from a specific operator.
// If the operator is self, we call the local handler directly.
// Otherwise, we make a gRPC call to the peer operator.
func (s *TpreServer) getPartialEcdhFromOperator(
	ctx context.Context,
	operator *so.SigningOperator,
	ephemeralPubKey []byte,
) (*pbtpre.PartialEcdhShareResponse, error) {
	requestID := fmt.Sprintf("tpre-%s", operator.Identifier[:8])

	// For self: call local handler directly
	if operator.Identifier == s.config.Identifier {
		return s.GetPartialEcdhShare(ctx, &pbtpre.PartialEcdhShareRequest{
			RequestId:          requestID,
			EphemeralPublicKey: ephemeralPubKey,
			KeyshareId:         "", // Uses default keyshare for PoC
		})
	}

	// For remote operators: make gRPC call
	conn, err := operator.NewOperatorGRPCConnection()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to operator %s: %w", operator.Identifier[:8], err)
	}
	defer conn.Close()

	client := pbtpre.NewTpreServiceClient(conn)
	return client.GetPartialEcdhShare(ctx, &pbtpre.PartialEcdhShareRequest{
		RequestId:          requestID,
		EphemeralPublicKey: ephemeralPubKey,
		KeyshareId:         "", // Uses default keyshare for PoC
	})
}

// operatorIdentifierToIndex converts a hex operator identifier to a 1-based index.
// The identifiers are like "0000...0001", "0000...0002", etc.
func (s *TpreServer) operatorIdentifierToIndex(identifier string) uint32 {
	op, ok := s.config.SigningOperatorMap[identifier]
	if !ok {
		return 0
	}
	// Operator IDs are 0-based internally, FROST indices are 1-based
	return uint32(op.ID) + 1
}

// getSigningKeyPackage retrieves the FROST signing key package for this operator.
// For PoC: returns the first available key package from the database.
func (s *TpreServer) getSigningKeyPackage(ctx context.Context, keyshareID string) (*pbfrost.KeyPackage, error) {
	// Get DB client from context (injected by DatabaseSessionMiddleware)
	dbClient, err := ent.GetDbFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get database client: %w", err)
	}

	// Query the first available signing keyshare
	// In production, keyshareID would specify which one to use.
	keyshares, err := dbClient.SigningKeyshare.Query().
		Limit(1).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query signing keyshares: %w", err)
	}
	if len(keyshares) == 0 {
		return nil, fmt.Errorf("no signing keyshares available")
	}

	ks := keyshares[0]

	// Build the KeyPackage proto from the stored keyshare
	// keys.Private.Serialize() returns []byte (32 bytes)
	// keys.Public.Serialize() returns []byte (33 bytes compressed)
	return &pbfrost.KeyPackage{
		Identifier:  string(s.config.Identifier),
		SecretShare: ks.SecretShare.Serialize(),
		PublicKey:   ks.PublicKey.Serialize(),
		MinSigners:  uint32(s.config.Threshold),
	}, nil
}
