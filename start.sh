#!/bin/bash
echo "--- ENVIRONMENT DIAGNOSTICS ---"
echo "Binary Paths:"
which python3 || echo "python3 not in path"
which python || echo "python not in path"
echo "Versions:"
python3 --version 2>&1 || echo "python3 --version failed"
python --version 2>&1 || echo "python --version failed"
echo "Current directory: $(pwd)"
echo "-------------------------------"

cd backend && python3 -m gunicorn main:app -w 1 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT
