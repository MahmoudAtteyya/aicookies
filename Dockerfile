FROM python:3.13-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app.py .
COPY templates/ templates/

# Create data directory for SQLite
RUN mkdir -p /data

EXPOSE 5050

ENV PYTHONUNBUFFERED=1

CMD ["python3", "app.py"]
