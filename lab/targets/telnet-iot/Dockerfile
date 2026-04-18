FROM debian:bullseye-slim

LABEL maintainer="Andre Henrique (@mrhenrike) | Uniao Geek"
LABEL description="Simulated Mirai-targeted Telnet IoT device for EmbedXPL-Forge lab"

# Install telnet daemon and tools
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        telnetd \
        xinetd \
        inetutils-inetd \
        procps \
        netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

# Create users with Mirai default credentials
# root:root, admin:admin, root:vizxv, guest:guest, admin:1234, root:888888
RUN echo 'root:root' | chpasswd && \
    useradd -m -s /bin/bash admin 2>/dev/null || true && \
    echo 'admin:admin' | chpasswd && \
    useradd -m -s /bin/bash guest 2>/dev/null || true && \
    echo 'guest:guest' | chpasswd

# Configure xinetd for telnet on ports 23 and 2323
COPY telnet-23.conf /etc/xinetd.d/telnet-23
COPY telnet-2323.conf /etc/xinetd.d/telnet-2323

# Simulate a BusyBox-like banner
RUN echo 'BusyBox v1.28.4 (2018-11-27 17:45:01 UTC) built-in shell (ash)' > /etc/motd && \
    echo 'Enter "help" for a list of built-in commands.' >> /etc/motd

EXPOSE 23 2323

CMD ["xinetd", "-dontfork"]
