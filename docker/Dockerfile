# Native control plane built from the distributed wheel; vendor/ is never copied.
FROM python:3.11-slim@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534 AS build
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip wheel --no-cache-dir --wheel-dir /wheels ".[api,report]"

FROM python:3.11-slim@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 OLYMPUS_STATE_DIR=/data/state
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels "olympus-security[api,report]" \
    && rm -rf /wheels \
    && groupadd --gid 10001 olympus \
    && useradd --uid 10001 --gid 10001 --no-create-home olympus \
    && mkdir /data && chown 10001:10001 /data
USER 10001:10001
WORKDIR /data
EXPOSE 8443 8600
ENTRYPOINT ["olympus"]
CMD ["themis", "serve"]
