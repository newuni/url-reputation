FROM python:3.12-slim

WORKDIR /app

# Install system dependencies for DNS/WHOIS lookups
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils \
    whois \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY pyproject.toml README.md ./
COPY url_reputation/ ./url_reputation/
COPY web/ ./web/

# Install the package and web dependencies
RUN pip install --no-cache-dir . fastapi uvicorn[standard]

# Expose port
EXPOSE 8000

# Run the API server
CMD ["uvicorn", "web.api:app", "--host", "0.0.0.0", "--port", "8000"]
