# --------------------------------------------
# ✅ Final fixed Dockerfile for Django + Gunicorn
# --------------------------------------------

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# 🧩 Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc build-essential curl \
    && rm -rf /var/lib/apt/lists/*

# 🧩 Install Python packages
COPY requirements.txt .
RUN python -m ensurepip --upgrade && \
    pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt && \
    pip install gunicorn

# 🧩 Copy the Django project
COPY . .

# 🧩 Collect static files
RUN python manage.py collectstatic --noinput || true

EXPOSE 8000

# 🧩 Start Gunicorn
CMD ["bash", "-c", "python manage.py migrate && exec gunicorn weaponpowercloud_backend.wsgi:application --bind 0.0.0.0:8000 --workers 3"]
