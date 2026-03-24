#!/bin/bash
set -e

VERSION=$(cat VERSION)
IMAGE="sre-report-analyzer"

echo "==> SRE Report Analyzer v${VERSION}"
echo ""

# Stop any existing container gracefully
if docker ps -q --filter "name=${IMAGE}" | grep -q .; then
  echo "==> Stopping existing container ..."
  docker-compose down
fi

# Build the Docker image from source
echo "==> Building Docker image (first run may take a few minutes) ..."
docker build \
  --build-arg APP_VERSION="${VERSION}" \
  -t "${IMAGE}:${VERSION}" \
  -t "${IMAGE}:latest" \
  .

# Ensure required data files and folders exist
mkdir -p uploads
touch suspicious_domains.csv tenant_exceptions.csv suspicious_usernames.csv

# Start the container
echo "==> Starting container ..."
docker-compose up -d

echo ""
echo "==> SRE Report Analyzer v${VERSION} is running."
echo "    Open in your browser: http://localhost:5000"
