#!/bin/bash

# Exit on error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}>>> Running tests...${NC}"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install test requirements
pip install -r requirements-test.txt

# Run tests with coverage
pytest --cov=AI_MAL --cov-report=term-missing --cov-report=html

# Deactivate virtual environment
deactivate

echo -e "${GREEN}>>> Tests complete!${NC}"
echo -e "${GREEN}>>> Coverage report generated in htmlcov/index.html${NC}" 