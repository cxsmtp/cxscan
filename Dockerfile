# syntax=docker/dockerfile:1
#
# cxscan image: orchestrator + KICS + 2ms (bundled) + git.
# SCA Resolver and the legacy CxSAST CLI are NOT redistributable via public
# images — mount them at runtime (see volumes below) or add an authenticated
# fetch step. Pin every version; "latest" makes a security gate non-reproducible.
#
# HEAVY-IMAGE WARNING: to actually resolve dependencies, SCA Resolver needs the
# real package managers (maven, gradle, npm, pip, nuget, go, ...) present. Add
# only the ecosystems your customers use; installing all of them bloats the image
# and widens its attack surface. Resolving untrusted source is code execution —
# run that path sandboxed.

ARG TWOMS_VERSION=3.0.0
ARG KICS_VERSION=2.1.3

FROM checkmarx/2ms:${TWOMS_VERSION} AS twoms
FROM checkmarx/kics:${KICS_VERSION} AS kics

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      git ca-certificates default-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# OSS engines (verify COPY source paths against the pulled images)
COPY --from=twoms /usr/bin/2ms /usr/local/bin/2ms
COPY --from=kics  /app/bin/kics /usr/local/bin/kics
COPY --from=kics  /app/bin/assets /opt/kics/assets
ENV KICS_QUERIES_PATH=/opt/kics/assets/queries

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY static ./static
COPY config.example.yaml .

# Mount at runtime:
#   -v /opt/cx/ScaResolver:/opt/cx/ScaResolver      (SCA Resolver binary + config.yml)
#   -v /opt/cx/cxsast-cli:/opt/cx/cxsast-cli         (legacy CxSAST runCxConsole)
# Pass engine creds as env (CXSAST_*, CXSCA_*, GIT_*) — never bake into the image.
ENV PATH="/opt/cx/cxsast-cli/bin:/opt/cx/ScaResolver:${PATH}"
EXPOSE 8080
CMD ["uvicorn", "app.app:app", "--host", "0.0.0.0", "--port", "8080"]
