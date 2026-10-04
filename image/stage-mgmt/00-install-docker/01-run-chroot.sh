#!/bin/bash -e

systemctl enable docker
usermod -aG docker "${FIRST_USER_NAME}"

# Passwordless sudo, as stock Raspberry Pi OS sets up for its first user (pi-gen
# only writes it from the first-boot wizard, which this image skips).
install -m 0440 /dev/stdin "/etc/sudoers.d/010_${FIRST_USER_NAME}-nopasswd" <<SUDOERS
${FIRST_USER_NAME} ALL=(ALL) NOPASSWD: ALL
SUDOERS
visudo -c -f "/etc/sudoers.d/010_${FIRST_USER_NAME}-nopasswd"
