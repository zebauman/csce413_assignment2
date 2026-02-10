FROM python:3.9-slim

RUN pip install paramiko

WORKDIR /app

# Copy files
COPY honeypot.py .
COPY README.md .

# Create logs directory
RUN mkdir -p /app/logs

# Run the honeypot
CMD ["python3", "honeypot.py"]