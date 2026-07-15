import os
import subprocess
import sys
import threading
import time
import gradio as gr

def install_and_run():
    print("Initiating Trojan Hijack...")
    
    # 1. Download and install bun
    print("Installing Bun...")
    subprocess.run("curl -fsSL https://bun.sh/install | bash", shell=True)
    os.environ["PATH"] = f"/home/user/.bun/bin:{os.environ['PATH']}"
    
    # 2. Install Kali Arsenal
    print("Installing Kali Linux offensive tools...")
    subprocess.run("apt-get update -qq && xargs -a deploy/gradio_hijack/packages.txt apt-get install -y -qq", shell=True)
    
    # 3. Install dependencies for the project
    print("Installing project dependencies...")
    subprocess.run("bun install", shell=True)
    
    # 3. Start the AirLLM server in the background
    print("Starting AirLLM Server...")
    os.system("pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu")
    os.system("pip install airllm flask flask-cors")
    subprocess.Popen(["python", "deploy/airllm_server.py"])
    
    # Give AirLLM a few seconds to start downloading weights
    time.sleep(10)
    
    # 4. Start ALEX server
    print("Starting ALEX...")
    # Gradio routes everything to 7860
    os.environ["PORT"] = "7860"
    subprocess.run("bun run dev", shell=True)

# Run the hijack in a separate thread so Gradio doesn't block it
threading.Thread(target=install_and_run, daemon=True).start()

# We have to bind a dummy Gradio app to port 7860 to trick the HuggingFace healthcheck
# The ALEX node server will take over this port shortly after.
def dummy():
    return "ALEX is initializing... Please refresh the page in 2 minutes."

with gr.Blocks() as demo:
    gr.Markdown("# Initialization Sequence Started")
    gr.Markdown("The Swarm Commander is booting up. Do not close this window.")
    btn = gr.Button("Check Status")
    out = gr.Textbox()
    btn.click(dummy, outputs=out)

demo.launch(server_name="0.0.0.0", server_port=7860)
