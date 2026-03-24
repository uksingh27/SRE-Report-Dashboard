#!/bin/bash
set -e

VERSION=$(cat VERSION)
IMAGE="sre-report-analyzer"
TAR_FILE="${IMAGE}-v${VERSION}.tar"

echo "==> SRE Report Analyzer v${VERSION}"
echo ""

# Check for the image tar
if [ ! -f "${TAR_FILE}" ]; then
  echo "ERROR: ${TAR_FILE} not found in the current directory."
  echo "       Make sure you are running this from inside the unzipped package folder."
  exit 1
fi

# Stop any existing container gracefully
if docker ps -q --filter "name=${IMAGE}" | grep -q .; then
  echo "==> Stopping existing container ..."
  docker-compose down
fi

# Load the Docker image
echo "==> Loading Docker image (this may take a moment) ..."
docker load -i "${TAR_FILE}"

# Ensure required data files and folders exist
mkdir -p uploads
touch suspicious_domains.csv tenant_exceptions.csv suspicious_usernames.csv

# Start the container
echo "==> Starting container ..."
docker-compose up -d

echo ""
echo "==> SRE Report Analyzer v${VERSION} is running."
echo "    Open in your browser: http://localhost:5000"
