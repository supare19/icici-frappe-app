#!/bin/bash
# Script to push to GitHub repository 'icici'
# Replace YOUR_USERNAME with your actual GitHub username

echo "Enter your GitHub username:"
read GITHUB_USERNAME

if [ -z "$GITHUB_USERNAME" ]; then
    echo "Error: GitHub username is required"
    exit 1
fi

echo "Adding remote origin..."
git remote add origin https://github.com/${GITHUB_USERNAME}/icici.git 2>/dev/null || git remote set-url origin https://github.com/${GITHUB_USERNAME}/icici.git

echo "Setting branch to main..."
git branch -M main

echo "Pushing to GitHub..."
git push -u origin main

echo "Done! Your repository is now on GitHub at: https://github.com/${GITHUB_USERNAME}/icici"

