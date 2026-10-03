#!/bin/bash -e

# Apply cybics-mgmt.txt before the network and the containers come up.
cat > /etc/systemd/system/cybics-mgmt-config.service <<'UNIT'
[Unit]
Description=CybICS-mgmt: apply cybics-mgmt.txt from the boot partition
DefaultDependencies=no
After=local-fs.target
RequiresMountsFor=/boot/firmware
Before=NetworkManager.service docker.service cybics-mgmt.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/cybics-mgmt-config
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT

# Load the container images once, on the first boot.
cat > /etc/systemd/system/cybics-mgmt-first-boot.service <<'UNIT'
[Unit]
Description=CybICS-mgmt: load the container images (first boot only)
After=docker.service
Requires=docker.service
ConditionPathExists=/opt/cybics-mgmt/images

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'for img in /opt/cybics-mgmt/images/*.tar; do echo "Loading $img"; docker load -i "$img"; done'
ExecStartPost=/bin/rm -rf /opt/cybics-mgmt/images
ExecStartPost=/bin/systemctl disable cybics-mgmt-first-boot.service
RemainAfterExit=yes
TimeoutStartSec=1800

[Install]
WantedBy=multi-user.target
UNIT

# The server and its proxy, the same compose stack as in the repository.
cat > /etc/systemd/system/cybics-mgmt.service <<'UNIT'
[Unit]
Description=CybICS-mgmt containers
After=docker.service cybics-mgmt-first-boot.service cybics-mgmt-config.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/cybics-mgmt
ExecStart=/usr/bin/docker compose up -d --remove-orphans
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
UNIT

# Address, Wi-Fi and admin password on the console login screen.
cat > /etc/systemd/system/cybics-mgmt-issue.service <<'UNIT'
[Unit]
Description=CybICS-mgmt: show how to connect on the console
After=cybics-mgmt.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/cybics-mgmt-issue
TimeoutStartSec=180

[Install]
WantedBy=multi-user.target
UNIT

systemctl enable cybics-mgmt-config.service cybics-mgmt-first-boot.service cybics-mgmt.service \
    cybics-mgmt-issue.service
