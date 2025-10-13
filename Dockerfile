# --------------------------------------------
# ✅ Django Production Dockerfile (Fixed Version)
# --------------------------------------------

# Use official Python runtime as base image
FROM python:3.11-slim

# Set environment variables to optimize Python
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive

# Set work directory
WORKDIR /app

# --------------------------------------------
# Install system dependencies (build tools + image libs)
# --------------------------------------------
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    libpq-dev \
    libjpeg-dev \
    zlib1g-dev \
    libfreetype6-dev \
    liblcms2-dev \
    libopenjp2-7-dev \
    libtiff5-dev \
    libwebp-dev \
    tk-dev \
    tcl-dev \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# --------------------------------------------
# Optional: Oracle Instant Client (only if needed)
# --------------------------------------------
RUN mkdir -p /opt/oracle && \
    cd /opt/oracle && \
    wget https://download.oracle.com/otn_software/linux/instantclient/instantclient-basiclite-linuxx64.zip && \
    unzip instantclient-basiclite-linuxx64.zip && \
    rm -f instantclient-basiclite-linuxx64.zip && \
    cd /opt/oracle/instantclient* && \
    rm -f *jdbc* *occi* *mysql* *README *jar uidrvci genezi adrci && \
    echo /opt/oracle/instantclient* > /etc/ld.so.conf.d/oracle-instantclient.conf && \
    ldconfig

ENV LD_LIBRARY_PATH=/opt/oracle/instantclient_21_13:$LD_LIBRARY_PATH

# --------------------------------------------
# Install Python dependencies
# --------------------------------------------
COPY requirements.txt /app/
RUN pip install --upgrade pip setuptools wheel \
    && pip install -r requirements.txt

# --------------------------------------------
# Copy project files
# --------------------------------------------
COPY . /app/

# Create necessary directories
RUN mkdir -p /app/logs /app/staticfiles /app/media

# Collect static files (ignore errors if DEBUG=True)
RUN python manage.py collectstatic --noinput || true

# Expose port 8000
EXPOSE 8000

# --------------------------------------------
# Run migrations and start Gunicorn server
# --------------------------------------------
CMD ["sh", "-c", "python manage.py migrate && gunicorn weaponpowercloud_backend.wsgi:application --bind 0.0.0.0:8000"]

