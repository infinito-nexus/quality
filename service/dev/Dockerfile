FROM docker:29.0.1-cli
RUN apk add --no-cache python3  # nocheck: coding.dockerfile -- DL3018: the tag docker:29.0.1-cli fixes the Alpine release, whose repository keeps only the current python3 build, so a pinned version breaks the build at its next point release
COPY ansible/roles/web-app-cst-quality-check/files/python/script.py /launcher.py
HEALTHCHECK NONE
ENTRYPOINT ["sh", "-c", "while true; do python3 /launcher.py /etc/quality-check/config.json; sleep 3; done"]
