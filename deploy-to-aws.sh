#!/bin/bash
echo "========================================="
echo "  WeaponBackend - EC2 Deployment"
echo "========================================="

# Navigate to project directory
cd ~/weapons || cd /home/ubuntu/weapons || cd /home/ec2-user/weapons

# Stop existing containers
echo "[1/6] Stopping existing containers..."
docker-compose -f docker-compose.prod.yml down

# Pull latest code
echo "[2/6] Pulling latest code from GitHub..."
git pull origin main

# Check if .env exists
if [ ! -f .env ]; then
    echo "[3/6] ERROR: .env file not found!"
    echo "Please create .env file with production credentials"
    exit 1
fi
echo "[3/6] .env file found ✓"

# Rebuild images
echo "[4/6] Building Docker images (this may take a few minutes)..."
docker-compose -f docker-compose.prod.yml build --no-cache

# Start services
echo "[5/6] Starting services..."
docker-compose -f docker-compose.prod.yml up -d

# Wait for services to start
echo "[6/6] Waiting for services to start..."
sleep 10

# Check status
echo ""
echo "========================================="
echo "  Deployment Status"
echo "========================================="
docker-compose -f docker-compose.prod.yml ps

echo ""
echo "========================================="
echo "  Recent Logs"
echo "========================================="
docker-compose -f docker-compose.prod.yml logs --tail=50 web

echo ""
echo "To view live logs: docker-compose -f docker-compose.prod.yml logs -f web"
echo "To create super admin: docker exec weaponbackend_web_prod python add_super_admin_user.py"