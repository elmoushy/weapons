# --------------------------------------------
# ✅ Django Production Dockerfile (with Pillow-SIMD fix)
# --------------------------------------------

FROM python:3.11-slim

# Environment setup
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# 🧩 Install build and image libraries
RUN apt-get update && apt-get install -y \
    gcc g++ make \
    libjpeg-dev zlib1g-dev libfreetype6-dev liblcms2-dev \
    libopenjp2-7-dev libtiff5-dev libwebp-dev \
    libpq-dev tk-dev tcl-dev wget unzip \
    && rm -rf /var/lib/apt/lists/*

# Optional: Oracle Instant Client (only if your project really uses it)
# RUN mkdir -p /opt/oracle && cd /opt/oracle && \
#     wget https://download.oracle.com/otn_software/linux/instantclient/instantclient-basiclite-linuxx64.zip && \
#     unzip instantclient-basiclite-linuxx64.zip && \
#     rm -f instantclient-basiclite-linuxx64.zip && \
#     cd /opt/oracle/instantclient* && ldconfig

# Install Python deps
COPY requirements.txt .
RUN pip install --upgrade pip setuptools wheel \
    && pip install -r requirements.txt

# Copy project
COPY . .

# Collect static files
RUN python manage.py collectstatic --noinput || true

EXPOSE 8000

# 🐍 Start with Gunicorn (production)
CMD ["sh", "-c", "python manage.py migrate && gunicorn weaponpowercloud_backend.wsgi:application --bind 0.0.0.0:8000"]
