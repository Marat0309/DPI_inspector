#!/usr/bin/env bash
set -e

echo "[*] Checking bash syntax..."
bash -n dpi_check.sh
bash -n harden_nginx.sh

echo "[*] Checking python syntax..."
python3 -m py_compile protocol_infer.py quic_probe.py

echo "[✓] Validation passed"
