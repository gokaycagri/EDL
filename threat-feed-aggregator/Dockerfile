# Use an official Python runtime as a parent image
FROM python:3.13-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV TZ=UTC

# Install system dependencies (including tzdata for timezone support)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tzdata \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application source code
COPY threat_feed_aggregator/ threat_feed_aggregator/

# Create a directory for persistent data
RUN mkdir -p data

# Expose the port the app runs on
EXPOSE 443

# Healthcheck to ensure the service is running
# Note: curl -k is needed for self-signed certs
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f -k https://localhost:443/status || exit 1

# Run the application
CMD ["python", "-m", "threat_feed_aggregator.app"]
