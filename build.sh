#!/bin/bash
set -e

VERSION=$(cat VERSION)
IMAGE="sre-report-analyzer"

echo "==> Building ${IMAGE}:${VERSION} ..."
docker build \
  --build-arg APP_VERSION="${VERSION}" \
  -t "${IMAGE}:${VERSION}" \
  -t "${IMAGE}:latest" \
  .

echo ""
echo "==> Done. Image tagged as:"
echo "    ${IMAGE}:${VERSION}"
echo "    ${IMAGE}:latest"
echo ""
docker images "${IMAGE}"
