FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg iptables iproute2 procps kmod \
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

# WSL2 config: auto-start Docker daemon on boot
RUN printf '[boot]\ncommand=/usr/bin/dockerd &>/var/log/dockerd.log\n\n[network]\ngenerateResolvConf=true\n' \
    > /etc/wsl.conf

CMD ["/bin/bash"]
