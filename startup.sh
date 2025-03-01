#!/bin/bash

echo "=== Starting RunPod Spam Filter Setup ==="

# Move to the workspace directory
cd /workspace

# Remove the old repo to get a completely fresh copy
echo "Removing old repository..."
rm -rf spam_filter

# Clone the latest repo from GitHub
echo "Cloning fresh repository..."
git clone https://github.com/nitchmaa/spam_filter.git
cd spam_filter

# Ensure Python dependencies are installed
echo "Installing dependencies..."
pip3 install --upgrade pip
pip3 install -r requirements.txt

# Run the spam filter script
echo "Starting ai_spam_filter.py..."
nohup python3 ai_spam_filter.py > output.log 2>&1 &

echo "=== Setup Complete! The script is now running. Check output.log for details. ==="
