# One simulated machine (Main, an edge or the lab). Each runs its own Docker
# daemon, so the repo's compose files run inside it unchanged, with the same
# addresses, port bindings and host-network services as on the real node.
FROM docker:29-dind AS docker

FROM ubuntu:24.04
# extra_ca: the SIM_EXTRA_CA bundle (empty unless behind a TLS-inspecting proxy).
RUN --mount=type=secret,id=extra_ca,target=/tmp/extra-ca.crt \
    apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates iptables bash curl openssl dnsutils rsync jq iproute2 procps \
        python3 python3-pip tzdata xz-utils \
    && cat /tmp/extra-ca.crt >> /etc/ssl/certs/ca-certificates.crt \
    && pip install --no-cache-dir --break-system-packages \
        "psycopg[binary,pool]==3.3.6" "mmdb-writer==0.2.5" "netaddr==1.3.0" \
    && rm -rf /var/lib/apt/lists/*

# Docker engine, CLI and plugins from the official dind image.
COPY --from=docker /usr/local/bin/ /usr/local/bin/
COPY --from=docker /usr/local/libexec/docker/ /usr/local/libexec/docker/
RUN update-alternatives --set iptables /usr/sbin/iptables-legacy \
    && update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy

COPY entrypoint.sh /usr/local/bin/sim-node
ENTRYPOINT ["/usr/local/bin/sim-node"]
