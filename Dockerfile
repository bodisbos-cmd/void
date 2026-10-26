# syntax=docker/dockerfile:1

FROM ghcr.io/xtls/xray-core:26.9.8 AS xray

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    XRAY_BIN=/usr/local/bin/xray \
    COOKIE_SECURE=1

# Keep package indexes and downloaded .deb files in BuildKit caches rather
# than the image layer. Rebuilds can reuse them without inflating the image.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl nginx gosu \
 && rm -f /etc/nginx/sites-enabled/default

# Copy the official Xray binary from the upstream, version-pinned image.
COPY --from=xray /usr/local/bin/xray /usr/local/bin/xray
RUN /usr/local/bin/xray version

WORKDIR /app
COPY requirements.txt ./requirements.txt
# Runtime bytecode is disabled above, so compiling package bytecode during
# install only adds build time and image size without being reused at runtime.
RUN --mount=type=cache,target=/root/.cache/pip pip install --no-compile -r requirements.txt
COPY app ./app
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY nginx/default.conf /etc/nginx/conf.d/default.conf
COPY scripts/start.sh /usr/local/bin/abyss-start
RUN chmod 0755 /usr/local/bin/abyss-start \
 && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin abyss \
 && mkdir -p /data /tmp/nginx-client-body /tmp/nginx-proxy /tmp/nginx-fastcgi /tmp/nginx-uwsgi /tmp/nginx-scgi \
 && chown -R abyss:abyss /data /tmp/nginx-client-body /tmp/nginx-proxy /tmp/nginx-fastcgi /tmp/nginx-uwsgi /tmp/nginx-scgi

# Start as root only so the mounted Railway volume can be fixed at runtime.
# The web application itself is launched as the unprivileged abyss user.
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=45s --retries=3 CMD curl -fsS http://127.0.0.1:8080/health || exit 1
CMD ["/usr/local/bin/abyss-start"]
