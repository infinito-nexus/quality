FROM quality-check/scan:local AS trusting
COPY certificate.pem /etc/ssl/test/certificate.pem
ENV GIT_SSL_CAINFO=/etc/ssl/test/certificate.pem
HEALTHCHECK NONE

FROM trusting AS probe
COPY probe.py /opt/probe/quality
COPY probe.py /opt/probe/git
ENV PATH=/opt/probe:/bin
HEALTHCHECK NONE
