# SmartWatch monitor image, built from this repository (no third-party Python package is installed;
# add "cryptography" with --build-arg EXTRAS=[jwt] for RS256/ES256/EdDSA tokens).
# Pin the base image by digest for production:
#   docker buildx imagetools inspect python:3.12-slim   -> use python:3.12-slim@sha256:<digest>
FROM python:3.12-slim

ARG EXTRAS=""
RUN useradd --create-home --uid 10001 smartwatch && mkdir -p /data && chown smartwatch /data
WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN python -m pip install --no-cache-dir ".${EXTRAS}" && rm -rf /src

USER smartwatch
WORKDIR /data
EXPOSE 8730
# Credentials come from the environment (SMARTWATCH_INGEST_TOKEN, SMARTWATCH_OPERATOR_TOKEN and a JWT key);
# the monitor refuses to start without the two tokens. The policy is mounted at /config/policy.json.
HEALTHCHECK --interval=10s --timeout=2s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8730/healthz', timeout=2)"
ENTRYPOINT ["sf-smartwatch", "serve", "--host", "0.0.0.0", "--port", "8730", "--policy", "/config/policy.json", \
            "--audit", "/data/audit.jsonl"]
