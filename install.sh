#!/bin/bash

# Recon Tool Installation Script
# This script sets up the reconnaissance tool with all dependencies

echo "🔍 Recon Tool Installation Script"
echo "================================="
echo

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3 first."
    exit 1
fi

echo "✅ Python 3 found: $(python3 --version)"

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is not installed. Please install pip3 first."
    exit 1
fi

echo "✅ pip3 found"

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "📚 Installing requirements..."
pip install -r requirements.txt

# Make scripts executable
echo "🔧 Making scripts executable..."
chmod +x *.py

# Create output directory
echo "📁 Creating output directory..."
mkdir -p recon_results

echo
echo "✅ Installation completed successfully!"
echo
echo "🚀 To run the tool:"
echo "   source venv/bin/activate  # Activate virtual environment"
echo "   python main.py example.com"
echo
echo "📖 For more information, see README.md"
echo
echo "⚠️  Remember to only use this tool on domains you own or have permission to test."