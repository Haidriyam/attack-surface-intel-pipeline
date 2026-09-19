FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pipeline/ pipeline/

USER 10001
CMD ["python", "-c", "from pipeline.collector import ReconTelemetryCollector; print('Recon Pipeline Online.')"]