FROM nixos/nix:2.35.2 AS closure
ARG PACKAGE
WORKDIR /build
COPY flake.nix flake.lock ./
RUN test -n "${PACKAGE}" \
 && nix --extra-experimental-features "nix-command flakes" build "path:/build#${PACKAGE}" --out-link /package \
 && mkdir -p /image/nix/store /image/bin /image/etc/ssl/certs /image/src /image/tmp \
 && nix-store --query --requisites /package > /tmp/closure \
 && while read -r path; do cp -a "$path" /image/nix/store/ || exit 1; done < /tmp/closure \
 && ln -s "$(readlink -f /package)"/bin/* /image/bin/ \
 && chown 65534:65534 /image/src \
 && chmod 1777 /image/tmp

FROM closure AS scan-closure
RUN ln -s "$(readlink -f /package)/etc/ssl/certs/ca-bundle.crt" /image/etc/ssl/certs/ca-bundle.crt \
 && printf '#!/bin/sh\nexec python3 -c "import sys; from quality.cli import main; sys.exit(main(sys.argv[1:]))" "$@"\n' > /image/bin/quality \
 && chmod 0555 /image/bin/quality

FROM scratch AS scan
COPY --from=scan-closure /image/ /
COPY src /opt/quality/src
COPY rules /opt/quality/rules
ENV PATH=/bin \
    PYTHONPATH=/opt/quality/src \
    PYTHONDONTWRITEBYTECODE=1 \
    SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt \
    GIT_SSL_CAINFO=/etc/ssl/certs/ca-bundle.crt
USER 65534:65534
WORKDIR /src
HEALTHCHECK NONE

FROM scratch AS proxy
COPY --from=closure /image/ /
COPY service/nix/squid.conf /etc/squid/squid.conf
ENV PATH=/bin
USER 65534:65534
EXPOSE 3128
ENTRYPOINT ["squid", "-N", "-f", "/etc/squid/squid.conf"]
