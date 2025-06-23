FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libc6-dev \
    libffi-dev \
    libssl-dev \
    netcat-openbsd \
    iproute2 \
    iptables \
    tcpdump \
    net-tools \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create application directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY ev_charger_agent.py .
COPY wazuh_integration.py .
COPY traffic_generator.py .
COPY entrypoint.sh .

# Create necessary directories
RUN mkdir -p /var/log/ev-charger \
    && mkdir -p /var/log/wazuh \
    && mkdir -p /var/log/traffic

# Make entrypoint executable
RUN chmod +x entrypoint.sh

# Create non-root user for security
RUN useradd -r -s /bin/false evcharger \
    && chown -R evcharger:evcharger /app /var/log/ev-charger /var/log/wazuh /var/log/traffic

# Switch to non-root user
USER evcharger

# Expose ports that might be used
EXPOSE 1201 8080 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8080/health', timeout=5)" || exit 1

# Set entrypoint
ENTRYPOINT ["./entrypoint.sh"]