#!/usr/bin/env bash
set -euo pipefail

echo "🔻 Stopping containers..."
docker compose down

echo "📥 Fetching latest code..."
git fetch origin
git reset --hard origin/main

echo "🐳 Rebuilding containers..."
docker compose up -d --build

echo "🚀 Starting app service..."
docker compose up -d app

echo "📜 Showing app logs..."
docker compose logs --no-color app