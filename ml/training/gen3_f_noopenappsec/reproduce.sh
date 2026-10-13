#!/usr/bin/env bash
# Rebuild the Gen 3 model gen3_f_noopenappsec from the data in this folder.
#
# Restores CSIC 2010 + SR-BH 2020 to ml/dataset/ (checksums from the model card),
# then runs ml/train_final_gen3.py with the card's hyperparameters. The new model
# lands in ml/models/archive/gen3-final-f-noopenappsec-<time>/ and does not
# replace the served ml/models/gen3/gen3_f_noopenappsec.onnx.
#
# Usage (from anywhere): ml/training/gen3_f_noopenappsec/reproduce.sh
# PYTHON=/path/to/venv/bin/python to pick the interpreter (needs ml/requirements-train.txt).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ML="$(cd "$HERE/../.." && pwd)"
REPO="$(dirname "$ML")"
PY="${PYTHON:-python3}"
CARD="ml/models/gen3/gen3_f_noopenappsec_model_card.json"

# The builder trains on every source it finds. These were absent from the original
# run, so their presence would give a different model.
for f in dataset/vps_audit_labelled.jsonl dataset/nginx_real_benign.jsonl; do
  if [ -e "$ML/$f" ]; then
    echo "refusing: ml/$f exists and would be trained on; move it away first" >&2
    exit 1
  fi
done
if compgen -G "$ML/telemetry/*.jsonl" >/dev/null; then
  echo "refusing: ml/telemetry/*.jsonl exists and would be trained on; move it away first" >&2
  exit 1
fi

mkdir -p "$ML/dataset/external"
gunzip -c "$HERE/data/csic_final.csv.gz" > "$ML/dataset/csic_final.csv"
gunzip -c "$HERE/data/srbh2020_labelled.jsonl.gz" > "$ML/dataset/external/srbh2020_labelled.jsonl"
(cd "$ML" && sha256sum -c "$HERE/data/SHA256SUMS")

cd "$REPO"
PYTHONPATH=. "$PY" ml/train_final_gen3.py --exclude-dataset OpenAppSec --params-from "$CARD"
