# syntax=docker/dockerfile:1.5

FROM julia:1.10 AS builder

# System deps for native libs (LibPQ, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git build-essential pkg-config libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only dependency files first for better layer caching
COPY Project.toml ./

# Generate Manifest.toml and install dependencies
RUN julia --project=/app -e 'using Pkg; \
        Pkg.add(["HTTP", "JSON3", "StructTypes", "Oxygen", "LibPQ", "JSONWebTokens"]); \
        Pkg.instantiate()'

# Now copy the app code
COPY api.jl ./

FROM julia:1.10

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy pre-built depot and app
COPY --from=builder /root/.julia /root/.julia
COPY --from=builder /app /app

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=40s \
  CMD curl -f http://localhost:8080/health || exit 1

CMD ["julia", "--project=/app", "api.jl"]
