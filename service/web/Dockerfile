FROM python:3.14-slim-trixie AS widget
ADD --checksum=sha256:55c563b7441c94b12ef2344636e06c84d66afd455db809735c13eab8253fbb38 \
    https://registry.npmjs.org/altcha/-/altcha-3.5.0.tgz /tmp/altcha.tgz
RUN mkdir /widget \
 && tar -xzf /tmp/altcha.tgz -C /tmp \
    package/dist/external/altcha.min.js package/dist/external/altcha.css package/dist/workers/pbkdf2.js package/LICENSE.txt \
 && cp /tmp/package/dist/external/altcha.min.js /tmp/package/dist/external/altcha.css /tmp/package/dist/workers/pbkdf2.js /widget/ \
 && cp /tmp/package/LICENSE.txt /widget/LICENSE.txt

FROM python:3.14-slim-trixie
WORKDIR /app
COPY service/web/requirements.txt ./
RUN pip install --no-cache-dir --no-compile --root-user-action=ignore -r requirements.txt
COPY service/web/quality_web ./quality_web
COPY ansible/roles/web-app-cst-quality-check/files/python/script.py ./launcher.py
COPY --from=widget /widget ./quality_web/static/altcha
ENV PYTHONDONTWRITEBYTECODE=1
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --retries=6 CMD ["python3", "-c", "import urllib.request as u; u.urlopen(u.Request('http://127.0.0.1:8080/healthz', headers={'X-Real-IP': '127.0.0.1'}), timeout=4)"]
CMD ["gunicorn", "--workers=1", "--threads=8", "--bind=0.0.0.0:8080", "quality_web:create_app('/etc/quality-web/config.json')"]
