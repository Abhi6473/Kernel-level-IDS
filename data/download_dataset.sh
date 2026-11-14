#!/usr/bin/env bash
# Turnkey downloader for official CIC-IDS-2017 CSV dataset
set -euo pipefail

DATA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
URL="http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/MachineLearningCSV.zip"
ZIP_FILE="${DATA_DIR}/MachineLearningCSV.zip"

echo "==> Downloading official CIC-IDS-2017 archive (~230 MB)..."
curl -L -C - -o "${ZIP_FILE}" "${URL}"

echo "==> Extracting CSV files into ${DATA_DIR}..."
unzip -o "${ZIP_FILE}" -d "${DATA_DIR}"

echo "==> Cleaning up temporary zip archive..."
rm -f "${ZIP_FILE}"

echo "==> Successfully downloaded and extracted CIC-IDS-2017 dataset into data/!"
