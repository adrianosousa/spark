#!/bin/bash
# Restart all 5 operators in tmux session
set -e

RUN_DIR="/Users/adrianosousa/spark-tpre/_data/run_1"
SESSION="operators"

cd /Users/adrianosousa/spark-tpre

# Kill existing session
tmux kill-session -t "$SESSION" 2>/dev/null || true
sleep 1

# Create new session with first operator in first pane
tmux new-session -d -s "$SESSION"

for i in 0 1 2 3 4; do
    if [ $i -ne 0 ]; then
        tmux split-window -t "$SESSION" -v
        tmux select-layout -t "$SESSION" tiled
    fi

    PORT=$((8535 + i))

    # Copy config template
    cp so.template.config.yaml "temp_config_operator_${i}.dev.yaml"

    # Send command to the CURRENT pane (which is the one we just split)
    tmux send-keys -t "${SESSION}:0.${i}" "${RUN_DIR}/bin/operator -config temp_config_operator_${i}.dev.yaml -index ${i} -key ${RUN_DIR}/operator_${i}.key -operators ${RUN_DIR}/config.json -threshold 3 -signer unix:///tmp/frost_${i}.sock -port ${PORT} -database 'postgresql://127.0.0.1:5432/sparkoperator_${i}?sslmode=disable' -server-cert ${RUN_DIR}/server_${i}.crt -server-key ${RUN_DIR}/server_${i}.key -run-dir ${RUN_DIR} -local true 2>&1 | tee ${RUN_DIR}/logs/sparkoperator_${i}_restart2.log" C-m
done

echo "All 5 operators started in tmux session: $SESSION"
