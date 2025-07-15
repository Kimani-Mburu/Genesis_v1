# Multi-stage build for GENESIS Agent
FROM ubuntu:20.04 as builder

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    libjson-c-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Build the application
RUN mkdir build && cd build && \
    cmake .. && \
    cmake --build . --parallel $(nproc)

# Runtime stage
FROM ubuntu:20.04 as runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl1.1 \
    libjson-c4 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 genesis && \
    mkdir -p /app/data /app/logs && \
    chown -R genesis:genesis /app

# Copy built executable
COPY --from=builder /app/build/genesis-agent /app/
COPY --from=builder /app/build/lib*.so* /app/ 2>/dev/null || true

# Set ownership
RUN chown genesis:genesis /app/genesis-agent

# Switch to non-root user
USER genesis

# Set working directory
WORKDIR /app

# Expose default port for agent communication
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep genesis-agent || exit 1

# Run the agent
CMD ["./genesis-agent"]