#!/usr/bin/env bash
# Update geoip.dat and geosite.dat from runetfreedom/russia-v2ray-rules-dat
set -euo pipefail

GEO_DIR="/opt/xray-proxy/config"
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

REPO="https://github.com/runetfreedom/russia-v2ray-rules-dat"
API="https://api.github.com/repos/runetfreedom/russia-v2ray-rules-dat/releases/latest"

echo "Fetching latest release info…"
RELEASE_JSON=$(curl -sfL --connect-timeout 15 "$API")
TAG=$(echo "$RELEASE_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['tag_name'])")
echo "Latest tag: $TAG"

BASE_URL="$REPO/releases/download/$TAG"

echo "Downloading geoip.dat…"
curl -sfL --connect-timeout 30 -o "$TMP/geoip.dat"   "$BASE_URL/geoip.dat"
echo "Downloading geosite.dat…"
curl -sfL --connect-timeout 30 -o "$TMP/geosite.dat" "$BASE_URL/geosite.dat"

# Verify files are not empty
[ -s "$TMP/geoip.dat" ]   || { echo "ERROR: geoip.dat is empty"; exit 1; }
[ -s "$TMP/geosite.dat" ] || { echo "ERROR: geosite.dat is empty"; exit 1; }

# Atomic replace
cp "$TMP/geoip.dat"   "$GEO_DIR/geoip.dat"
cp "$TMP/geosite.dat" "$GEO_DIR/geosite.dat"

echo "Done: $(du -sh $GEO_DIR/geoip.dat $GEO_DIR/geosite.dat)"
