# Dockerfile
FROM julia:1.10

# Install system dependencies
RUN apt-get update && apt-get install -y \
    postgresql-client \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy project files
COPY Project.toml .

# Install Julia dependencies
RUN julia -e 'using Pkg; Pkg.activate("."); Pkg.instantiate(); Pkg.precompile()'

# Install JWT package from GitHub (not in General registry yet)
RUN julia -e 'using Pkg; Pkg.activate("."); Pkg.add(url="https://github.com/felipenoris/JSONWebTokens.jl"); Pkg.precompile()'

# Copy application code
COPY api.jl .

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the application
CMD ["julia", "api.jl"]