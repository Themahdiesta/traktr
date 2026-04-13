# ╔════════════════════════════════════════════════════════════════════╗
# ║  TRAKTR v2.0 -- Multi-stage Docker Build                        ║
# ╚════════════════════════════════════════════════════════════════════╝

# ── Stage 1: Go tool builder ────────────────────────────────────────────
FROM golang:1.22-bookworm AS go-builder

RUN go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest

# ── Stage 2: Runtime ───────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/root/go/bin:/usr/local/go/bin:${PATH}"

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash curl wget jq python3 python3-pip \
    nmap nikto whatweb git xxd bc gawk \
    chromium chromium-driver \
    && rm -rf /var/lib/apt/lists/*

# Python tools
RUN pip3 install --break-system-packages \
    arjun uro

# Copy Go binaries from builder
COPY --from=go-builder /go/bin/* /usr/local/bin/

# Update nuclei templates
RUN nuclei -update-templates 2>/dev/null || true

# Install Traktr
WORKDIR /opt/traktr
COPY . .
RUN chmod +x src/core/traktr.sh src/core/installer.sh && \
    ln -sf /opt/traktr/src/core/traktr.sh /usr/local/bin/traktr

# Default output directory
RUN mkdir -p /output /root/.traktr

ENTRYPOINT ["traktr"]
CMD ["--help"]
