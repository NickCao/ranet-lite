FROM debian:trixie-slim

ENV container=oci

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bird2 \
        charon-systemd \
        iproute2 \
        libcharon-extra-plugins \
        libstrongswan-extra-plugins \
        libstrongswan-standard-plugins \
        strongswan-swanctl \
        systemd \
    && rm -rf /var/lib/apt/lists/*

COPY strongswan.conf /etc/strongswan.conf
COPY bird.conf /etc/bird/bird.conf
COPY ranet-link.service /etc/systemd/system/ranet-link.service
COPY ranet-ready.service /etc/systemd/system/ranet-ready.service
COPY ranet.target /etc/systemd/system/ranet.target
COPY systemd-console.conf /etc/systemd/system.conf.d/console.conf

RUN systemctl set-default ranet.target \
    && systemctl mask \
        console-getty.service \
        getty@tty1.service \
        systemd-udev-trigger.service \
        systemd-udevd-control.socket \
        systemd-udevd-kernel.socket \
        systemd-udevd.service

EXPOSE 13000/udp

STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd", "--log-level=info", "--show-status=yes"]
