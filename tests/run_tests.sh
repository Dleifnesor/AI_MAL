#!/bin/bash

# Exit on error
set -e

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install test requirements
pip install -r requirements-test.txt

# Run tests with coverage
pytest --cov=ai_mal --cov-report=term-missing --cov-report=html

# Deactivate virtual environment
deactivate 