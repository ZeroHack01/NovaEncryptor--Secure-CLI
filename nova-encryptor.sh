#!/bin/bash
# NovaEncryptor v2.0 Launcher

# Check if virtual environment exists
if [ ! -d "nova_env" ]; then
    echo "❌ Virtual environment not found. Run setup.py first."
    exit 1
fi

# Activate virtual environment and run
source nova_env/bin/activate
python src/nova_encryptor.py "$@"
