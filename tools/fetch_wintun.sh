#!/usr/bin/env bash
set -euf -o pipefail
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

WINTUN_URL="https://www.wintun.net/builds/wintun-0.9.2.zip"
WINTUN_SHA="984b2db0b4e7742653797db197df5dabfcbb5a5ed31e75bada3b765a002fc8ce"

wget "$WINTUN_URL" -O "${DIR}/wintun.zip"
mkdir -p "${DIR}/../third_party/wintun"
unzip "${DIR}/wintun.zip" -d "${DIR}/../third_party/"
rm "${DIR}/wintun.zip"

echo "Assuming on x86_64"
cp "${DIR}/../third_party/wintun/bin/amd64/wintun.dll" "${DIR}/../wintun.dll"
