FROM python:3.13-slim

WORKDIR /app

# Install system deps for Playwright + Chromium
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget ca-certificates fonts-liberation libasound2 libatk-bridge2.0-0 \
    libatk1.0-0 libcups2 libdrm2 libgbm1 libgtk-3-0 libnspr4 libnss3 \
    libxcomposite1 libxdamage1 libxfixes3 libxkbcommon0 libxrandr2 \
    xdg-utils libu2f-udev libvulkan1 \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright Chromium
RUN python3 -m playwright install chromium
RUN python3 -m playwright install-deps chromium

# Copy application
COPY app.py .
COPY templates/ templates/

# Create data directory
RUN mkdir -p /data

EXPOSE 5050

ENV PYTHONUNBUFFERED=1
ENV PLAYWRIGHT_BROWSERS_PATH=/root/.cache/ms-playwright

# Production WSGI with gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5050", "--workers", "2", "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
