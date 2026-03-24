#!/bin/bash
set -e

VERSION=$(cat VERSION)

echo "==> SRE Report Analyzer - First Time Setup (v${VERSION})"
echo ""

# Ensure runtime data files exist on host (volumes mount these into container)
mkdir -p uploads
touch suspicious_domains.csv tenant_exceptions.csv suspicious_usernames.csv

# Build the image
bash build.sh

# Start the container
docker-compose up -d

echo ""
echo "==> Setup complete! v${VERSION} is running."
echo "    Open: http://localhost:5000"
