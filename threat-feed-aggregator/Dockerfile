# Base Image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies (needed for some python packages like cryptography)
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create necessary directories for volumes
RUN mkdir -p /app/data /app/config /app/certs

# Expose HTTPS port
EXPOSE 443

# Environment variables
ENV PYTHONUNBUFFERED=1

# Run the application
CMD ["python", "-m", "threat_feed_aggregator.app"]
