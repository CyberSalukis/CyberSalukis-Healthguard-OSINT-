FROM python:3.11-slim

LABEL maintainer="IEEE CyberSalukis"
LABEL description="IEEE CyberSalukis HealthGuard OSINT — Healthcare AI Attack Surface Reconnaissance"
LABEL org.opencontainers.image.source="https://github.com/[YOUR-ORG]/IEEE-CyberSalukis-HealthGuard-OSINT"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Create output directory
RUN mkdir -p /app/output /app/reports

# Default config (user mounts their own config.yaml)
RUN cp config/config.example.yaml config/config.yaml

VOLUME ["/app/config", "/app/output"]

ENTRYPOINT ["python", "healthguard.py"]
CMD ["--help"]
