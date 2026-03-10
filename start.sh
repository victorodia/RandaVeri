#!/bin/bash
# Deployment Trigger: Railway Nixpacks Fix v2
echo "--- ENVIRONMENT DIAGNOSTICS ---"
echo "Binary Paths:"
which python3 || echo "python3 not in path"
which python || echo "python not in path"
echo "Searching for python3..."
find / -name "python3" -type f -executable 2>/dev/null | head -n 3
echo "Versions:"
python3 --version 2>&1 || echo "python3 --version failed"
echo "Current directory: $(pwd)"
echo "-------------------------------"

# Try to run gunicorn directly or via python3 module
cd backend && {
    python3 -m gunicorn main:app -w 1 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT || \
    gunicorn main:app -w 1 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT
}
