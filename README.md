# Spark T-PRE: Threshold Proxy Re-Encryption for Bitcoin L2

> **Proof of Concept** — Threshold cryptographic content key recovery on the Spark operator federation, enabling offline paywalled content delivery on P2P networks.

This is a fork of [Spark](https://github.com/lightsparkdev/spark) (Lightspark's Bitcoin L2 protocol) extended with **Threshold Proxy Re-Encryption (T-PRE)** — a new operator capability that enables content creators to monetize encrypted content without being online when readers pay.

---

## The Problem

P2P content platforms face a fundamental tension: **paywalled content requires the author to be online** to deliver decryption keys after payment. This breaks the P2P promise of censorship resistance and availability.

Current approaches (like Hyperswarm-based key delivery) require a live connection between author and reader. If the author is offline, asleep, or behind a NAT — the reader pays but can't access the content.

Existing threshold decryption solutions (e.g. LIT Protocol, NuCypher/TACo) address this on EVM chains but require their own dedicated networks, their own tokens, and their own infrastructure. There is no Bitcoin-native solution.

## The Solution

T-PRE leverages the **existing** Spark operator federation (5 operators with FROST threshold keys from DKG) to act as a **threshold decryption oracle** — requiring zero additional infrastructure, zero new tokens, and no dependency on EVM chains:

1. **Author publishes**: Encrypts content with a random key, seals that key to the federation's threshold public key via ECIES
2. **Reader pays**: Submits a Spark transfer to the author (Bitcoin L2 payment)
3. **Reader unlocks**: Requests the federation to threshold-decrypt the content key — no author involvement needed
4. **Federation responds**: 3-of-5 operators perform partial ECDH using their FROST key shares, coordinator combines shares via Lagrange interpolation, recovers the content key

The author can be completely offline. The federation never learns the content — only the 32-byte symmetric key transits through the coordinator operator transiently.

## Live Demo: TzimTzum

This PoC is integrated with [TzimTzum](https://github.com/adrianosousa/tzimtzum), a P2P content platform built on [Pear Runtime](https://pears.com) (Hyperswarm + Hyperbee). The end-to-end flow has been tested and verified:

- Author publishes a paywalled article on TzimTzum (content encrypted with XSalsa20-Poly1305, key sealed to federation via ECIES)
- Author **goes completely offline** (closes the app)
- Reader discovers the author's content, sees the paywalled article with a "T-PRE Enabled — Author can be offline" badge
- Reader clicks unlock, the Bare process shells out to `grpcurl` which calls the federation's `TpreService/request_re_encryption` endpoint
- Federation threshold-decrypts the content key and returns it
- Reader decrypts the article content locally

**Result**: Paywalled content unlocked with the author offline. Decryption took ~200ms via the local federation.

---

## Architecture

```
    Author (publish)                    Federation (5 operators)               Reader (unlock)
    ================                    ========================               ===============

    content_key = random(32)
    encrypted = secretbox(content, key)
    sealed_key = ECIES(key, PK_fed)     ┌──────────────────────┐
    post = {encrypted, sealed_key}       │  FROST Key Shares    │
            │                            │  from DKG:           │
            │  (author goes offline)     │  sk = Σ λᵢ·skᵢ      │
            ▼                            │  PK_fed = sk·G       │               sealed_key from post
                                         └──────────────────────┘                       │
                                                    ▲                                   │
                                                    │ gRPC                              ▼
                                                    │                          grpcurl → TpreService
                                                    │                          /request_re_encryption
                                                    │                                   │
                                         ┌──────────┴──────────┐                        │
                                         │ Coordinator (op 0)  │◄───────────────────────┘
                                         │                     │
                                         │ 1. Extract R from   │
                                         │    sealed_key       │
                                         │ 2. Compute own      │
                                         │    partial ECDH:    │
                                         │    S₀ = sk₀ · R     │
                                         │ 3. Collect shares   │──── GetPartialEcdhShare ──►┌─────────┐
                                         │    from peers       │◄── S₁ = sk₁ · R ──────────│ Op 1..4 │
                                         │ 4. Lagrange:        │                            └─────────┘
                                         │    S = Σ λᵢ·Sᵢ     │
                                         │ 5. KDF(S) → AES key │
                                         │ 6. Decrypt → key    │
                                         │ 7. Return key       │
                                         └─────────────────────┘
                                                    │
                                                    │ content_key
                                                    ▼
                                            Reader decrypts content
                                            with secretbox(key, nonce)
```

### Why This Works

ECIES decryption is fundamentally an ECDH operation: `shared_secret = sk · R`, where `sk` is the recipient's private key and `R` is the ephemeral public key from the ciphertext.

Since the federation's private key `sk` is Shamir-shared across operators via FROST DKG (`sk = Σ λᵢ·skᵢ`), we can split the ECDH:

- Each operator computes: `Sᵢ = skᵢ · R` (partial ECDH with their key share)
- Coordinator combines: `S = Σ λᵢ · Sᵢ = (Σ λᵢ·skᵢ) · R = sk · R`

Scalar multiplication distributes over elliptic curve point addition — the same mathematical property that makes FROST threshold signing possible also enables threshold decryption.

---

## Components

### Rust Signer (`signer/spark-frost/`)

| File | Description |
|------|-------------|
| `src/tpre.rs` | Threshold ECIES decryption: partial ECDH, Lagrange interpolation, HKDF key derivation, AES-256-GCM decryption. Full compatibility with the `ecies` crate v0.2 format. |
| `src/lib.rs` | Module registration |
| `Cargo.toml` | Added `ecies`, `k256`, `elliptic-curve` dependencies |

New gRPC methods in `server.rs`:
- `ThresholdDecryptReencrypt` — Coordinator entry point: collects partial ECDH shares from peers, combines via Lagrange, decrypts, returns content key
- `GetPartialEcdhShare` — Peer method: computes `skᵢ · R` and returns the partial ECDH point

### Go Operator (`spark/so/`)

| File | Description |
|------|-------------|
| `grpc/tpre_server.go` | `TpreService` gRPC server — coordinates the threshold decryption across operators. Calls `ThresholdDecryptReencrypt` on local FROST signer, which in turn calls `GetPartialEcdhShare` on peer signers. |
| `authn/unauthenticated.go` | Auth bypass for T-PRE service (PoC only) |
| `bin/operator/grpc.go` | Service registration |

### Protocol Definitions (`protos/`)

| File | Description |
|------|-------------|
| `tpre.proto` | `TpreService` with `request_re_encryption` RPC |
| `frost.proto` | Added `ThresholdDecryptReencrypt` and `GetPartialEcdhShare` RPCs, `content_key` field in response |

### ECIES Format

Matches the Rust `ecies` crate v0.2.x default configuration:

```
Ciphertext: [65-byte uncompressed ephemeral R] [16-byte nonce] [16-byte tag] [encrypted data]
Key derivation: HKDF-SHA256(ikm = R_uncompressed || shared_point_uncompressed, salt=None, info=empty)
Encryption: AES-256-GCM with 16-byte nonce
```

---

## Running the Local Federation

### Prerequisites

```bash
brew install postgresql tmux zeromq pkgconf grpcurl
```

Ensure PostgreSQL is running with databases `sparkoperator_0` through `sparkoperator_4`.

### Build

```bash
# Build the Go operator
cd spark && go build -o bin/operator/sparkoperator ./bin/operator

# Build the Rust signer
cd signer && cargo build

# Generate proto files (if modified)
make
```

### Start the Federation

```bash
# Start everything (bitcoind, operators, signers, LRC20)
./run-everything.sh

# Or restart just the operators (after rebuilding)
./restart-operators.sh
```

The federation runs 5 operators on ports 8535-8539, each with a FROST signer on a Unix socket (`/tmp/frost_0.sock` through `/tmp/frost_4.sock`).

### Verify T-PRE

```bash
# Generate a test payload (ECIES-sealed content key)
cd signer/spark-frost && cargo run --example gen_test_payload > /tmp/payload.json

# Call the federation
grpcurl -insecure \
  -import-path protos -proto tpre.proto \
  -d "$(cat /tmp/payload.json)" \
  localhost:8535 tpre.TpreService/request_re_encryption
```

Expected response includes `contentKey` (base64-encoded content key recovered via threshold decryption).

---

## Road to Production

This PoC demonstrates the cryptographic feasibility and end-to-end flow. Moving to production would require:

### Authentication & Authorization
- **Remove the auth bypass** for `TpreService` in `unauthenticated.go` — the PoC bypasses `authn.Interceptor` for the entire T-PRE service
- **Add payment verification**: the coordinator should verify the Spark transfer (`transfer_id`) before releasing the content key, using the existing transfer validation infrastructure
- **Add mTLS or IP-based auth** for the internal `GetPartialEcdhShare` calls between operators (currently unauthenticated)

### Payment Atomicity
- **Adaptor signatures**: bind the content key release to payment completion — the reader can only obtain the key by revealing a secret that completes the Spark transfer, making payment and decryption atomic
- **Anti-replay**: track (post_id, reader_pubkey) pairs to prevent re-requesting already-delivered keys

### Security Hardening
- **Memory zeroization**: ensure the content key is purged from coordinator memory immediately after returning to the reader (currently relies on Go/Rust garbage collection)
- **Rate limiting**: prevent abuse of the threshold decryption oracle
- **Audit logging**: record all T-PRE requests for compliance

### Protocol Improvements
- **Native gRPC client**: replace the `grpcurl` subprocess with a proper gRPC-web client or Connect protocol handler, eliminating the dependency on an external binary
- **SDK integration**: add `requestReEncryption()` to the official Spark JS/TypeScript SDK

### Scalability
- **Caching**: cache recently-decrypted content keys (per reader) to avoid repeated threshold operations
- **Batch operations**: allow multiple content keys to be decrypted in a single federation round-trip

---

## Related

- [Spark Protocol](https://github.com/lightsparkdev/spark) — Bitcoin L2 by Lightspark
- [TzimTzum](https://github.com/adrianosousa/tzimtzum) — P2P content platform (Pear Runtime) with T-PRE paywall integration
- [FROST](https://eprint.iacr.org/2020/852) — Flexible Round-Optimized Schnorr Threshold Signatures
- [Pear Runtime](https://pears.com) — P2P application runtime (Hyperswarm + Hypercore)

---

*Built by [Reshimu Labs](https://reshimulabs.com) as a proof of concept for threshold cryptographic content delivery on Bitcoin L2.*
