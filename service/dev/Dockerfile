FROM docker:29.0.1-cli
RUN apk add --no-cache python3
COPY ansible/roles/web-app-cst-quality-check/files/python/script.py /launcher.py
ENTRYPOINT ["sh", "-c", "while true; do python3 /launcher.py /etc/quality-check/config.json; sleep 3; done"]
