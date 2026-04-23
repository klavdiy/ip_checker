#!/bin/bash

# Setup script for IP Address Checker
# Скрипт установки для IP Address Checker

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "================================"
echo "IP Address Checker - Setup"
echo "================================"
echo ""

# Check Python 3
echo "1. Checking Python 3 installation..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed"
    echo "   Install via: brew install python3"
    exit 1
else
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo "✅ Python 3 found: $PYTHON_VERSION"
fi

# Make scripts executable
echo ""
echo "2. Making scripts executable..."
chmod +x "$SCRIPT_DIR/ip_checker.sh"
chmod +x "$SCRIPT_DIR/ip_checker.py"
echo "✅ Scripts are now executable"

# Check database exists
echo ""
echo "3. Checking database file..."
if [ -f "$SCRIPT_DIR/asn_database.json" ]; then
    echo "✅ Database file found: asn_database.json"
else
    echo "❌ Database file not found"
    exit 1
fi

# Create necessary directories
echo ""
echo "4. Setting up directories..."
mkdir -p "$SCRIPT_DIR"
echo "✅ Directories ready"

# Test installation
echo ""
echo "5. Running test scan..."
cd "$SCRIPT_DIR"
python3 ip_checker.py -h > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✅ Installation test passed"
else
    echo "❌ Installation test failed"
    exit 1
fi

echo ""
echo "================================"
echo "Setup completed successfully! ✅"
echo "================================"
echo ""
echo "Quick start examples:"
echo ""
echo "1. Check single IP:"
echo "   ./ip_checker.sh -i 83.1.1.1"
echo ""
echo "2. Check IP range:"
echo "   ./ip_checker.sh -r 83.0.0.1 83.0.0.255"
echo ""
echo "3. Check ASN:"
echo "   ./ip_checker.sh -a AS12389"
echo ""
echo "4. Save results to file:"
echo "   ./ip_checker.sh -i 83.1.1.1 -s"
echo ""
echo "For full documentation, read: README.md"
echo ""
