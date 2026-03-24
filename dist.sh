#!/bin/bash
set -e

VERSION=$(cat VERSION)
IMAGE="sre-report-analyzer"
DIST_NAME="${IMAGE}-v${VERSION}"
DIST_ARCHIVE="${DIST_NAME}.tar.gz"

echo "==> Packaging SRE Report Analyzer v${VERSION} (source distribution) ..."

# Clean up any previous dist staging folder
rm -rf "${DIST_NAME}" "${DIST_ARCHIVE}"
mkdir -p "${DIST_NAME}"

# --- App source files ---
cp app.py main_processor.py config.py requirements.txt "${DIST_NAME}/"
cp Dockerfile .dockerignore docker-compose.yml VERSION "${DIST_NAME}/"

# --- Processors and templates ---
cp -r processors/ templates/ "${DIST_NAME}/"

# --- Reference data (seed CSVs) ---
cp suspicious_domains.csv tenant_exceptions.csv suspicious_usernames.csv "${DIST_NAME}/"

# --- Script colleagues will use ---
cp load-and-run.sh "${DIST_NAME}/"
chmod +x "${DIST_NAME}/load-and-run.sh"

# --- Install instructions (placed at root of package for visibility) ---
cp docs/install.md "${DIST_NAME}/INSTALL.md"

# --- Clean up any Python cache that got copied ---
find "${DIST_NAME}" -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "${DIST_NAME}" -name "*.pyc" -delete 2>/dev/null || true

# --- Create compressed tar ---
echo "==> Compressing to ${DIST_ARCHIVE} ..."
tar -czf "${DIST_ARCHIVE}" "${DIST_NAME}/"
rm -rf "${DIST_NAME}"

echo ""
echo "==> Done!"
echo "    Package : ${DIST_ARCHIVE}"
echo "    Size    : $(du -sh ${DIST_ARCHIVE} | cut -f1)"
echo ""
echo "    Share ${DIST_ARCHIVE} with colleagues."
echo "    They extract it and run: ./load-and-run.sh"
