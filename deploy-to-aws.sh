#!/bin/bash

# =================================================================
# AWS EC2 Deployment Script for WeaponBackend
# =================================================================
# This script automates the deployment of the Django application
# to an AWS EC2 instance using Docker.
# =================================================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
APP_NAME="weaponbackend"
REPO_URL="https://github.com/elmoushy/WeaponBackend.git"
DEPLOY_DIR="/home/ubuntu/weaponbackend"
BRANCH="main"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  WeaponBackend AWS EC2 Deployment${NC}"
echo -e "${GREEN}========================================${NC}"

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}This script needs sudo privileges. Please enter your password if prompted.${NC}"
fi

# Step 1: Update system
echo -e "\n${GREEN}[1/10] Updating system packages...${NC}"
sudo apt-get update -y
sudo apt-get upgrade -y

# Step 2: Install Docker
echo -e "\n${GREEN}[2/10] Installing Docker...${NC}"
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    rm get-docker.sh
    echo -e "${GREEN}Docker installed successfully!${NC}"
else
    echo -e "${YELLOW}Docker is already installed.${NC}"
fi

# Step 3: Install Docker Compose
echo -e "\n${GREEN}[3/10] Installing Docker Compose...${NC}"
if ! command -v docker-compose &> /dev/null; then
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    echo -e "${GREEN}Docker Compose installed successfully!${NC}"
else
    echo -e "${YELLOW}Docker Compose is already installed.${NC}"
fi

# Step 4: Install Git
echo -e "\n${GREEN}[4/10] Installing Git...${NC}"
if ! command -v git &> /dev/null; then
    sudo apt-get install -y git
else
    echo -e "${YELLOW}Git is already installed.${NC}"
fi

# Step 5: Clone or update repository
echo -e "\n${GREEN}[5/10] Cloning/updating repository...${NC}"
if [ -d "$DEPLOY_DIR" ]; then
    echo -e "${YELLOW}Directory exists. Pulling latest changes...${NC}"
    cd $DEPLOY_DIR
    git pull origin $BRANCH
else
    echo -e "${GREEN}Cloning repository...${NC}"
    git clone -b $BRANCH $REPO_URL $DEPLOY_DIR
    cd $DEPLOY_DIR
fi

# Step 6: Check for .env file
echo -e "\n${GREEN}[6/10] Checking environment configuration...${NC}"
if [ ! -f ".env" ]; then
    echo -e "${RED}ERROR: .env file not found!${NC}"
    echo -e "${YELLOW}Please create .env file with your configuration:${NC}"
    echo -e "  1. Copy .env.production.example to .env"
    echo -e "  2. Edit .env with your actual values"
    echo -e "  3. Run this script again"
    echo -e "\nExample:"
    echo -e "  cp .env.production.example .env"
    echo -e "  nano .env  # Edit with your values"
    exit 1
else
    echo -e "${GREEN}.env file found!${NC}"
fi

# Step 7: Create necessary directories
echo -e "\n${GREEN}[7/10] Creating necessary directories...${NC}"
mkdir -p logs media staticfiles nginx/ssl

# Step 8: Stop existing containers
echo -e "\n${GREEN}[8/10] Stopping existing containers...${NC}"
docker-compose -f docker-compose.prod.yml down || true

# Step 9: Build and start containers
echo -e "\n${GREEN}[9/10] Building and starting Docker containers...${NC}"
docker-compose -f docker-compose.prod.yml up --build -d

# Step 10: Wait for services to be ready
echo -e "\n${GREEN}[10/10] Waiting for services to be ready...${NC}"
sleep 10

# Check if containers are running
if docker-compose -f docker-compose.prod.yml ps | grep -q "Up"; then
    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}  Deployment Completed Successfully!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo -e "\nYour application is now running!"
    echo -e "Access it at: ${YELLOW}http://$(curl -s ifconfig.me)${NC}"
    echo -e "\nUseful commands:"
    echo -e "  View logs:    ${YELLOW}docker-compose -f docker-compose.prod.yml logs -f${NC}"
    echo -e "  Restart:      ${YELLOW}docker-compose -f docker-compose.prod.yml restart${NC}"
    echo -e "  Stop:         ${YELLOW}docker-compose -f docker-compose.prod.yml down${NC}"
    echo -e "  Shell access: ${YELLOW}docker-compose -f docker-compose.prod.yml exec web bash${NC}"
else
    echo -e "\n${RED}Deployment failed! Please check the logs:${NC}"
    echo -e "${YELLOW}docker-compose -f docker-compose.prod.yml logs${NC}"
    exit 1
fi

# Reminder about .env file
echo -e "\n${YELLOW}========================================${NC}"
echo -e "${YELLOW}  IMPORTANT SECURITY REMINDER${NC}"
echo -e "${YELLOW}========================================${NC}"
echo -e "Make sure your .env file is secure and never committed to Git!"
echo -e "The .env file is already in .gitignore for your safety."
