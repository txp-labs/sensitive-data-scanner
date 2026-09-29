# Lambda container image for scheduled batch scans.
#
#   docker build -t sensitive-data-scanner .
#
# The entry point is the AWS Lambda runtime interface client; the handler is
# sensitive_data_scanner.handler.handler. Base images are pinned by digest so
# a release is reproducible from its tag. Python 3.12, Debian slim.

FROM ghcr.io/astral-sh/uv:0.12.20@sha256:100047e74f30778ab704942321a09750d6158739573ff58bf3924085cc6cd2d8 AS uv

FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS build
# binutils, for stripping debug symbols from shared libraries (build stage only).
RUN apt-get update \
 && apt-get install -y --no-install-recommends binutils \
 && rm -rf /var/lib/apt/lists/*
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_NO_CACHE=1 UV_PYTHON_DOWNLOADS=never
WORKDIR /src
COPY LICENSE NOTICE ./
COPY spec/ spec/
COPY schema/ schema/
COPY third_party/ third_party/
COPY scanner/ scanner/
COPY scripts/slim-site-packages.sh scripts/
# Locked, hash-checked dependencies (runtime + the Lambda runtime interface
# client), then the scanner itself, into one directory.
RUN cd scanner \
 && uv export --frozen --no-dev --group lambda --no-emit-project -o /tmp/requirements.txt \
 && uv pip install --python /usr/local/bin/python --target /opt/app --require-hashes -r /tmp/requirements.txt \
 && uv build --wheel --out-dir /tmp/dist \
 && uv pip install --python /usr/local/bin/python --target /opt/app --no-deps /tmp/dist/*.whl \
 && /src/scripts/slim-site-packages.sh /opt/app \
 && mkdir -p /opt/app/licenses \
 && cp /src/LICENSE /src/NOTICE /opt/app/licenses/ \
 && cp -r /src/third_party /opt/app/licenses/

FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
LABEL org.opencontainers.image.source="https://github.com/txp-labs/sensitive-data-scanner" \
      org.opencontainers.image.description="Sensitive data scanner: findings only, never values" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /opt/app /opt/app
ENV PYTHONPATH=/opt/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /opt/app
# Lambda runs the image as its own non-root user; this keeps a local `docker
# run` non-root too.
USER 65532:65532
ENTRYPOINT ["python", "-m", "awslambdaric"]
CMD ["sensitive_data_scanner.handler.handler"]
