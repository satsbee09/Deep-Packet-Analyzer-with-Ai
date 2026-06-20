#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_PCAP="$ROOT_DIR/tests/sample.pcap"
BUILD_BIN="$ROOT_DIR/build/deep_packet_analyzer"
LOG_FILE="$ROOT_DIR/tests/test.log"

if [ ! -f "$TEST_PCAP" ]; then
  echo "Sample PCAP not found: $TEST_PCAP"
  echo "Please download a sample PCAP into tests/sample.pcap"
  exit 2
fi

if [ ! -x "$BUILD_BIN" ]; then
  echo "Built binary not found or not executable: $BUILD_BIN"
  echo "Please build the project first (cmake .. && cmake --build . in build/)."
  exit 3
fi

mkdir -p "$(dirname "$LOG_FILE")"
echo "Running analyzer on $TEST_PCAP..."
"$BUILD_BIN" --offline "$TEST_PCAP" --log "$LOG_FILE"

echo "--- Last 50 lines of log ---"
tail -n 50 "$LOG_FILE" || true

echo "Test run complete."
