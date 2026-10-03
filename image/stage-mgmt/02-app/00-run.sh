#!/bin/bash -e

# Runs on the build host; files go into the image's root filesystem.
# image/build.sh staged the application (app/) and the arm64 container
# tarballs (containers/) next to this script.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

install -d -m 755 "${ROOTFS_DIR}/opt/cybics-mgmt"
cp -r "${SCRIPT_DIR}/app/." "${ROOTFS_DIR}/opt/cybics-mgmt/"

install -d -m 755 "${ROOTFS_DIR}/opt/cybics-mgmt/images"
cp "${SCRIPT_DIR}"/containers/*.tar "${ROOTFS_DIR}/opt/cybics-mgmt/images/"
ls -lh "${ROOTFS_DIR}/opt/cybics-mgmt/images/"

install -m 755 files/cybics-mgmt-config "${ROOTFS_DIR}/usr/local/sbin/cybics-mgmt-config"
install -m 755 files/cybics-mgmt-issue "${ROOTFS_DIR}/usr/local/sbin/cybics-mgmt-issue"

# The settings file lives on the boot partition, so it can be edited on any computer.
install -m 644 files/cybics-mgmt.txt "${ROOTFS_DIR}/boot/firmware/cybics-mgmt.txt"
