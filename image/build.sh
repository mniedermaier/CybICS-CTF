#!/bin/bash
#
# Build the CybICS-mgmt Raspberry Pi image: 64-bit Raspberry Pi OS Lite with
# the CybICS-mgmt containers pre-loaded and a Wi-Fi access point "cybics-mgmt".
# Runs on the Raspberry Pi 3, 4, 5 and Zero 2 W.
#
# Requirements: Docker with buildx (and binfmt/qemu for arm64 on an x86 host),
# about 10 GB of free disk space, the pi-gen submodule
# (git submodule update --init image/pi-gen).
#
# Usage: image/build.sh            output: image/deploy/*-CybICS-mgmt.img.xz
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
PIGEN_DIR="$SCRIPT_DIR/pi-gen"
STAGE_DIR="$SCRIPT_DIR/stage-mgmt"
APP_DIR="$STAGE_DIR/02-app/app"
CONTAINER_DIR="$STAGE_DIR/02-app/containers"
DEPLOY_DIR="$SCRIPT_DIR/deploy"

step() { echo -e "\033[0;32m==>\033[0m $1"; }
fail() { echo -e "\033[0;31mError:\033[0m $1" >&2; exit 1; }

# Architecture of the image inside a tarball from "buildx --output type=docker".
tarball_arch() {
    python3 - "$1" <<'PY' 2>/dev/null
import json, sys, tarfile

with tarfile.open(sys.argv[1]) as tf:
    def read(name):
        return json.load(tf.extractfile(name))

    manifest = read("manifest.json")[0]
    print(read(manifest["Config"]).get("architecture", ""))
PY
}

step "Checking prerequisites"
command -v docker >/dev/null || fail "Docker is not installed."
docker buildx version >/dev/null 2>&1 || fail "Docker buildx is not available."
[ -x "$PIGEN_DIR/build-docker.sh" ] || fail "pi-gen is missing. Run: git submodule update --init image/pi-gen"

step "Staging the application"
rm -rf "$APP_DIR" "$CONTAINER_DIR"
mkdir -p "$APP_DIR" "$CONTAINER_DIR" "$DEPLOY_DIR"
# The repository's compose file, without the build: the images are pre-loaded.
grep -v '^    build: \./server$' "$REPO_DIR/docker-compose.yml" > "$APP_DIR/docker-compose.yml"
cp -r "$REPO_DIR/proxy" "$APP_DIR/proxy"
SERVER_IMAGE="$(sed -n 's/^    image: \(cybics-mgmt-server:.*\)$/\1/p' "$REPO_DIR/docker-compose.yml")"
PROXY_IMAGE="$(sed -n 's/^    image: \(nginxinc\/.*\)$/\1/p' "$REPO_DIR/docker-compose.yml")"
[ -n "$SERVER_IMAGE" ] && [ -n "$PROXY_IMAGE" ] || fail "Cannot find the image names in docker-compose.yml."

step "Building the arm64 containers"
# Exporting a tarball needs a docker-container builder; the default "docker"
# driver cannot. Use $BUILDX_BUILDER if set, else a builder of our own.
BUILDER="${BUILDX_BUILDER:-cybics-mgmt-image}"
if ! docker buildx inspect "$BUILDER" >/dev/null 2>&1; then
    docker buildx create --name "$BUILDER" --driver docker-container >/dev/null
fi
docker buildx build --builder "$BUILDER" --platform linux/arm64 -t "$SERVER_IMAGE" \
    --output "type=docker,dest=$CONTAINER_DIR/cybics-mgmt-server.tar" "$REPO_DIR/server"
# The proxy image is re-exported through buildx rather than pulled, so the
# local Docker image store (and a running stack using it) is left alone.
PROXY_CONTEXT="$(mktemp -d)"
trap 'rm -rf "$PROXY_CONTEXT"' EXIT
echo "FROM $PROXY_IMAGE" > "$PROXY_CONTEXT/Dockerfile"
docker buildx build --builder "$BUILDER" --platform linux/arm64 -t "$PROXY_IMAGE" \
    --output "type=docker,dest=$CONTAINER_DIR/proxy.tar" "$PROXY_CONTEXT"

# Not only present, but arm64: an x86 container baked into the image would
# only fail on the Pi.
for tarball in "$CONTAINER_DIR"/*.tar; do
    arch="$(tarball_arch "$tarball")"
    [ "$arch" = "arm64" ] || fail "$(basename "$tarball") is '${arch:-unreadable}', expected arm64."
    echo "  $(basename "$tarball"): $(du -h "$tarball" | cut -f1), $arch"
done

step "Preparing pi-gen"
cp "$SCRIPT_DIR/config" "$PIGEN_DIR/config"
rm -rf "$PIGEN_DIR/stage-mgmt"
cp -r "$STAGE_DIR" "$PIGEN_DIR/stage-mgmt"
find "$PIGEN_DIR/stage-mgmt" -name "*.sh" -exec chmod +x {} \;
for stage in stage3 stage4 stage5; do
    touch "$PIGEN_DIR/$stage/SKIP" "$PIGEN_DIR/$stage/SKIP_IMAGES"
done
# stage2 is our base but carries EXPORT_IMAGE; do not export a plain Lite image.
touch "$PIGEN_DIR/stage2/SKIP_IMAGES"

step "Building the image (this takes a while)"
(cd "$PIGEN_DIR" && ./build-docker.sh)

step "Collecting the image"
shopt -s nullglob
images=("$PIGEN_DIR"/deploy/*CybICS-mgmt*.img.xz)
[ "${#images[@]}" -gt 0 ] || fail "pi-gen produced no image."
cp "${images[@]}" "$DEPLOY_DIR/"
ls -lh "$DEPLOY_DIR"/*.img.xz
echo
echo "Write it to an SD card (check the device with lsblk first):"
echo "  xzcat image/deploy/$(basename "${images[0]}") | sudo dd of=/dev/sdX bs=4M conv=fsync status=progress"
