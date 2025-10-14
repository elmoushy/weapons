
FROM python:3.10-slim

WORKDIR /app

# Install system dependencies for Oracle
RUN apt-get update && apt-get install -y \
    gcc \
    libaio1 \
    wget \
    unzip \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]