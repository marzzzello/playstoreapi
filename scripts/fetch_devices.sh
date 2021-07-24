#!/bin/bash

REPO_SRC="https://gitlab.com/AuroraOSS/gplayapi"
REPO_LOCAL="/tmp/psapi"
RES_DIR="${REPO_LOCAL}/src/main/resources"

DEVS_FILE="./playstoreapi/device.properties"

command -v git >/dev/null 2>&1 || {
    echo "git not installed"
    exit 1
}

if [ ! -d "./playstoreapi" ]; then
    echo "No playstoreapi dir found! Make sure you're in googleplay-api root dir"
    exit 1
fi

echo "==> Cloning play-store-api repo into $REPO_LOCAL"
git clone $REPO_SRC $REPO_LOCAL &>/dev/null

# clean device.properties file
echo "" >$DEVS_FILE

for dev in "$RES_DIR"/*; do
    NAME=$(basename "$dev" | sed -e "s/\(.*\).properties/\1/")
    echo "==> appending device data for $NAME"
    {
        echo "[$NAME]"
        cat "$dev"
        echo ""
    } >>$DEVS_FILE
done

# cleanup
echo "==> Cleanup"
rm -rf $REPO_LOCAL
