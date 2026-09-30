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
# Locked, hash-checked dependencies (runtime, the Lambda runtime interface
# client, and pyarrow for the columnar formats), then the scanner and its
# cloud-neutral core (scanner/core), into one directory. The Lambda zip has no pyarrow: it would not fit (see
# scripts/build-lambda-zip.sh).
RUN cd scanner \
 && uv export --frozen --no-default-groups --group lambda --group columnar --no-emit-workspace -o /tmp/requirements.txt \
 && uv pip install --python /usr/local/bin/python --target /opt/app --require-hashes -r /tmp/requirements.txt \
 && uv build --wheel --package sensitive-data-scanner-core --out-dir /tmp/dist \
 && uv build --wheel --package sensitive-data-scanner --out-dir /tmp/dist \
 && uv pip install --python /usr/local/bin/python --target /opt/app --no-deps /tmp/dist/*.whl \
 && /src/scripts/slim-site-packages.sh /opt/app \
 && mkdir -p /opt/app/licenses \
 && cp /src/LICENSE /src/NOTICE /opt/app/licenses/ \
 && cp -r /src/third_party /opt/app/licenses/

# ---------------------------------------------------------------------------
# The databases-anywhere runner (docs/DATABASES.md): a separate target, never
# the default. It carries the core and the drivers of the engines named in
# DB_EXTRAS (every engine by default; name fewer for a smaller image).
#
#   docker build --target db -t sensitive-data-scanner-db .
#   docker build --target db --build-arg DB_EXTRAS="postgresql mysql" -t sds-db-slim .
FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS db-build
ARG DB_EXTRAS="postgresql mysql sqlserver oracle mongodb snowflake databricks aws"
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
RUN cd scanner \
 && extras="" && for e in ${DB_EXTRAS}; do extras="${extras} --extra ${e}"; done \
 && uv export --frozen --package sensitive-data-scanner-db --no-default-groups ${extras} --no-emit-workspace -o /tmp/requirements.txt \
 && uv pip install --python /usr/local/bin/python --target /opt/app --require-hashes -r /tmp/requirements.txt \
 && uv build --wheel --package sensitive-data-scanner-core --out-dir /tmp/dist \
 && uv build --wheel --package sensitive-data-scanner-db --out-dir /tmp/dist \
 && uv pip install --python /usr/local/bin/python --target /opt/app --no-deps /tmp/dist/*.whl \
 && /src/scripts/slim-site-packages.sh /opt/app \
 && mkdir -p /opt/app/licenses \
 && cp /src/LICENSE /src/NOTICE /opt/app/licenses/ \
 && cp -r /src/third_party /opt/app/licenses/

FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS db
LABEL org.opencontainers.image.source="https://github.com/txp-labs/sensitive-data-scanner" \
      org.opencontainers.image.description="Sensitive data scanner for databases hosted anywhere: read-only, findings only, never values" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=db-build /opt/app /opt/app
ENV PYTHONPATH=/opt/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /opt/app
USER 65532:65532
ENTRYPOINT ["python", "-m", "sensitive_data_db"]
CMD ["scan"]

# ---------------------------------------------------------------------------
# The Azure scanner (docs/AZURE.md): a Container Apps job's image, a separate
# target, never the default. It carries the core, the Azure SDKs it reads with,
# pyarrow for the columnar formats, Event Grid for the optional push, and the
# drivers for Azure's databases (mssql-python, psycopg, PyMySQL).
#
#   docker build --target azure -t sensitive-data-scanner-azure .
FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS azure-build
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
RUN cd scanner \
 && uv export --frozen --package sensitive-data-scanner-azure --no-default-groups --extra all --no-emit-workspace -o /tmp/requirements.txt \
 && uv pip install --python /usr/local/bin/python --target /opt/app --require-hashes -r /tmp/requirements.txt \
 && uv build --wheel --package sensitive-data-scanner-core --out-dir /tmp/dist \
 && uv build --wheel --package sensitive-data-scanner-db --out-dir /tmp/dist \
 && uv build --wheel --package sensitive-data-scanner-azure --out-dir /tmp/dist \
 && uv pip install --python /usr/local/bin/python --target /opt/app --no-deps /tmp/dist/*.whl \
 && /src/scripts/slim-site-packages.sh /opt/app \
 && mkdir -p /opt/app/licenses \
 && cp /src/LICENSE /src/NOTICE /opt/app/licenses/ \
 && cp -r /src/third_party /opt/app/licenses/

FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS azure
# mssql-python's own ODBC driver links Kerberos and GSSAPI (it never uses them for an
# Entra token, but the library must load).
RUN apt-get update \
 && apt-get install -y --no-install-recommends libkrb5-3 libgssapi-krb5-2 \
 && rm -rf /var/lib/apt/lists/*
LABEL org.opencontainers.image.source="https://github.com/txp-labs/sensitive-data-scanner" \
      org.opencontainers.image.description="Sensitive data scanner for Azure: a Container Apps job, read-only, findings only, never values" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=azure-build /opt/app /opt/app
ENV PYTHONPATH=/opt/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /opt/app
USER 65532:65532
ENTRYPOINT ["python", "-m", "sensitive_data_azure"]
CMD ["scan"]

# ---------------------------------------------------------------------------
# The Google Cloud scanner (docs/GCP.md): a Cloud Run job's image, a separate
# target, never the default. It carries the core, google-auth (every Google API
# is called over REST: no gRPC stack), pyarrow for the columnar formats, and the
# drivers for Cloud SQL and AlloyDB (psycopg, PyMySQL).
#
#   docker build --target gcp -t sensitive-data-scanner-gcp .
FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS gcp-build
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
RUN cd scanner \
 && uv export --frozen --package sensitive-data-scanner-gcp --no-default-groups --extra all --no-emit-workspace -o /tmp/requirements.txt \
 && uv pip install --python /usr/local/bin/python --target /opt/app --require-hashes -r /tmp/requirements.txt \
 && uv build --wheel --package sensitive-data-scanner-core --out-dir /tmp/dist \
 && uv build --wheel --package sensitive-data-scanner-db --out-dir /tmp/dist \
 && uv build --wheel --package sensitive-data-scanner-gcp --out-dir /tmp/dist \
 && uv pip install --python /usr/local/bin/python --target /opt/app --no-deps /tmp/dist/*.whl \
 && /src/scripts/slim-site-packages.sh /opt/app \
 && mkdir -p /opt/app/licenses \
 && cp /src/LICENSE /src/NOTICE /opt/app/licenses/ \
 && cp -r /src/third_party /opt/app/licenses/

FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS gcp
LABEL org.opencontainers.image.source="https://github.com/txp-labs/sensitive-data-scanner" \
      org.opencontainers.image.description="Sensitive data scanner for Google Cloud: a Cloud Run job, read-only, findings only, never values" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=gcp-build /opt/app /opt/app
ENV PYTHONPATH=/opt/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /opt/app
USER 65532:65532
ENTRYPOINT ["python", "-m", "sensitive_data_gcp"]
CMD ["scan"]

# ---------------------------------------------------------------------------
# The Lambda image: the last stage, so a plain `docker build .` builds it.
FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS lambda
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
