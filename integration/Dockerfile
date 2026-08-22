FROM debian:bookworm-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        libcharon-extra-plugins \
        libstrongswan-extra-plugins \
        libstrongswan-standard-plugins \
        strongswan-charon \
        strongswan-swanctl \
    && rm -rf /var/lib/apt/lists/*

COPY strongswan.conf /etc/strongswan.conf
COPY start-strongswan /usr/local/bin/start-strongswan

EXPOSE 13000/udp

ENTRYPOINT ["/usr/local/bin/start-strongswan"]
