#!/bin/bash
echo "--- ENVIRONMENT DIAGNOSTICS ---"
echo "Check python: $(which python)"
echo "Check python3: $(which python3)"
echo "Python version: $(python --version 2>&1 || python3 --version 2>&1)"
echo "Available python binaries in /usr/bin: $(ls /usr/bin/python* | xargs)"
echo "Current directory: $(pwd)"
echo "Contents of backend/: $(ls -F backend/ | head -n 10)"
echo "-------------------------------"
cd backend && python3 -m gunicorn main:app -w 1 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT
