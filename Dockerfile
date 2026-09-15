# ── Stage 1: Build ───────────────────────────────────────────────────
FROM node:20-slim AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

# ── Stage 2: Runtime ─────────────────────────────────────────────────
FROM node:20-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Download sqlite-ai extension (Linux CPU x86_64, 2.4MB)
RUN mkdir -p /app/extensions && \
    curl -fSL "https://github.com/sqliteai/sqlite-ai/releases/download/1.0.4/ai-linux-cpu-x86_64-1.0.4.tar.gz" \
      -o /tmp/sqlite-ai.tar.gz && \
    tar -xzf /tmp/sqlite-ai.tar.gz -C /app/extensions && \
    rm /tmp/sqlite-ai.tar.gz && \
    ls -la /app/extensions/

# Download SmolLM2-135M-Instruct GGUF (138MB, CPU-friendly, 1-2GB RAM)
RUN mkdir -p /app/models && \
    curl -fSL "https://huggingface.co/HuggingFaceTB/SmolLM2-135M-Instruct-GGUF/resolve/main/smollm2-135m-instruct-q8_0.gguf" \
      -o /app/models/smollm2-135m-instruct-q8_0.gguf && \
    ls -lh /app/models/

# Install production dependencies only
COPY package*.json ./
RUN npm ci --omit=dev

# Copy built output from builder stage
COPY --from=builder /app/dist ./dist

# Create persistent data directory (Render disk mount point)
RUN mkdir -p /var/data

ENV NODE_ENV=production
ENV GUARD_DB_DIR=/var/data
ENV GUARD_MODEL_EXTENSION_PATH=/app/extensions/ai
ENV GUARD_MODEL_PATH=/app/models/smollm2-135m-instruct-q8_0.gguf
ENV GUARD_MODEL_GPU_LAYERS=0

EXPOSE 3000

CMD ["node", "dist/server.js"]
