#!/bin/bash -e

# Runs on the build host; files go into the image's root filesystem.
install -d -m 755 "${ROOTFS_DIR}/etc/NetworkManager/conf.d"
install -m 644 files/10-docker-unmanaged.conf "${ROOTFS_DIR}/etc/NetworkManager/conf.d/10-docker-unmanaged.conf"
install -d -m 755 "${ROOTFS_DIR}/etc/NetworkManager/system-connections"
install -m 600 files/cybics-mgmt-ap.nmconnection "${ROOTFS_DIR}/etc/NetworkManager/system-connections/"
