FROM python:3.12-slim

# tini: signal forwarding + zombie reaping (uvicorn/anyio children)
RUN apt-get update \
    && apt-get install -y --no-install-recommends tini curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m -u 1000 mcpuser && chown -R mcpuser:mcpuser /app
USER mcpuser

EXPOSE 8080

# Transport defaults to streamable-http; MCP_TRANSPORT=stdio for local clients
ENV MCP_TRANSPORT=streamable-http \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS "http://localhost:${MCP_PORT}/health" || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "main.py"]
