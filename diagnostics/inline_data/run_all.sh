#!/bin/sh
# Reproducible inline_data diagnostic for dissect.extfs.
# Builds four minimal ext4 images (clean + 3 corruption flavours), then runs the
# behavioural comparison and the reference-recovery demonstration.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="${PYTHON:-python3}"
cd "$HERE"
for mode in none bad_magic bad_value_offs entry_erased; do
    "$PY" build_image.py "$mode" "img_${mode}.img" >/dev/null
done
echo "################ CURRENT dissect.extfs BEHAVIOUR ################"
"$PY" summary.py
echo
echo "################ REFERENCE (KERNEL-SEMANTICS) RECOVERY ################"
"$PY" reference_fix.py
