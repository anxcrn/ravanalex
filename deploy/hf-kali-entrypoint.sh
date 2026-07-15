#!/bin/bash

# Start the AirLLM 70B API bridge in the background
echo "Starting AirLLM 70B Local API Bridge..."
python3 /opt/alex-llm/airllm_server.py &

# Wait a few seconds for Flask to initialize
sleep 5

# Start ALEX on port 7860 (HuggingFace requirement)
echo "Starting ALEX Autonomous Engine..."
export PORT=7860
bun run dev
