FROM debian:bookworm-slim

# systemd + systemd-sysv + dbus are REQUIRED: WSL only keeps a distro alive
# persistently when a real init (systemd PID 1) runs; without it WSL idle-shuts
# down the distro and the SIEM cannot survive a reboot. See resilience/REBOOT-SURVIVAL.md.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg iptables iproute2 procps kmod \
        systemd systemd-sysv dbus \
        git openssl dos2unix \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg \
       | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] \
       https://download.docker.com/linux/debian bookworm stable" \
       > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       docker-ce docker-ce-cli containerd.io docker-compose-plugin \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# WSL2 config: run systemd as PID 1 (it manages docker.service and, crucially,
# lets WSL keep the distro alive). setup-resilience.sh enables docker/containerd
# and installs the boot-convergence timer. NO manual dockerd boot command — that
# conflicts with systemd's docker.service.
RUN printf '[boot]\nsystemd=true\n\n[network]\ngenerateResolvConf=true\n' \
    > /etc/wsl.conf

CMD ["/bin/bash"]
