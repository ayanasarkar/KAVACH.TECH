# KAVACH on Render (or any container host): one image runs the console and, optionally, the bundled vulnerable lab.
FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY . .
# The module has no third-party dependencies, so there is nothing to download.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/vapt ./cmd/vapt \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/lab ./cmd/lab

FROM debian:bookworm-slim
# nmap and nikto give the agent its live network and web-server adapters. If a package is missing for this base image
# the build still succeeds and the console reports that tool as unavailable under the report's limitations.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates nmap \
 && (apt-get install -y --no-install-recommends nikto || echo "nikto not installable here: the console will report it as unavailable") \
 && rm -rf /var/lib/apt/lists/*
# Run unprivileged: nmap then uses TCP connect scans, which need no raw-socket capability.
RUN useradd --system --uid 10001 --create-home kavach && mkdir -p /data && chown kavach /data
WORKDIR /app
COPY --from=build /out/vapt /out/lab /app/
COPY scripts/render-start.sh /app/start.sh
RUN chmod +x /app/start.sh
# Safe defaults. Override any of them in the host's environment settings.
ENV VAPT_DATA=/data VAPT_LAB_ONLY=1 VAPT_RUN_LAB=1
USER kavach
EXPOSE 10000
CMD ["/app/start.sh"]
