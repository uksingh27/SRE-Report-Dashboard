#!/bin/bash
set -e

if [ -z "$1" ]; then
  echo "Usage: ./upgrade.sh <new-version>"
  echo "Example: ./upgrade.sh 2.3"
  exit 1
fi

NEW_VERSION="$1"
OLD_VERSION=$(cat VERSION)

echo "==> Upgrading SRE Report Analyzer from v${OLD_VERSION} to v${NEW_VERSION} ..."
echo ""

# Update VERSION file
echo "${NEW_VERSION}" > VERSION

# Build new image
bash build.sh

# Restart container with new image
docker-compose down
docker-compose up -d

echo ""
echo "==> Upgrade complete! Now running v${NEW_VERSION}."
echo "    Open: http://localhost:5000"
