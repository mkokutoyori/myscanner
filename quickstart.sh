#!/bin/bash

# VulnScan Platform Quick Start Script
# This script helps you get started with the VulnScan Platform quickly

set -e

echo "🛡️  VulnScan Platform - Quick Start"
echo "======================================"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first:"
    echo "   https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first:"
    echo "   https://docs.docker.com/compose/install/"
    exit 1
fi

echo "✅ Docker and Docker Compose are installed"
echo ""

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file from template..."
    cp .env.example .env
    echo "✅ .env file created. Please review and update it if needed."
    echo ""
fi

# Start services
echo "🚀 Starting VulnScan Platform services..."
echo ""
docker-compose up -d

echo ""
echo "⏳ Waiting for services to be ready (this may take 30-60 seconds)..."
sleep 10

# Check if services are running
echo ""
echo "🔍 Checking service health..."

# Check Postgres
if docker-compose ps postgres | grep -q "Up"; then
    echo "✅ PostgreSQL is running"
else
    echo "❌ PostgreSQL failed to start"
fi

# Check Redis
if docker-compose ps redis | grep -q "Up"; then
    echo "✅ Redis is running"
else
    echo "❌ Redis failed to start"
fi

# Check Vault
if docker-compose ps vault | grep -q "Up"; then
    echo "✅ Vault is running"
else
    echo "❌ Vault failed to start"
fi

# Check API
if docker-compose ps api | grep -q "Up"; then
    echo "✅ API is running"
else
    echo "❌ API failed to start"
fi

# Check Worker
if docker-compose ps worker | grep -q "Up"; then
    echo "✅ Worker is running"
else
    echo "❌ Worker failed to start"
fi

# Check Frontend
if docker-compose ps frontend | grep -q "Up"; then
    echo "✅ Frontend is running"
else
    echo "❌ Frontend failed to start"
fi

echo ""
echo "======================================"
echo "✅ VulnScan Platform is running!"
echo "======================================"
echo ""
echo "📌 Access Points:"
echo "   🌐 Web UI:       http://localhost:3000"
echo "   📖 API Docs:     http://localhost:8000/docs"
echo "   🔧 API Health:   http://localhost:8000/api/v1/health"
echo ""
echo "📚 Next Steps:"
echo "   1. Open http://localhost:3000 in your browser"
echo "   2. Navigate to 'Scans' and create a new Discovery Scan"
echo "   3. Enter target IPs (e.g., scanme.nmap.org)"
echo "   4. View discovered assets and findings"
echo ""
echo "🛑 To stop all services:"
echo "   docker-compose down"
echo ""
echo "📋 To view logs:"
echo "   docker-compose logs -f [service-name]"
echo "   Example: docker-compose logs -f api"
echo ""
echo "⚠️  LEGAL WARNING:"
echo "   Only scan systems you own or have written permission to test."
echo "   Unauthorized scanning is illegal."
echo ""
