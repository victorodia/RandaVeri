#!/bin/bash
echo "--- ENVIRONMENT DIAGNOSTICS ---"
echo "Python location: $(which python)"
echo "Python version: $(python --version)"
echo "Current directory: $(pwd)"
echo "Contents of backend/: $(ls -F backend/ | head -n 10)"
echo "-------------------------------"
cd backend && python -m gunicorn main:app -w 1 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT
