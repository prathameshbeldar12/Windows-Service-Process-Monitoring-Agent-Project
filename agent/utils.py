import os
import json
import socket
import hashlib
from agent.logger import agent_logger

def load_config():
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return json.load(f)
        else:
            agent_logger.warning("config.json not found, using default configuration.")
            return {}
    except Exception as e:
        agent_logger.error(f"Error loading config.json: {e}")
        return {}

def save_config(config_data):
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
    try:
        with open(config_path, 'w') as f:
            json.dump(config_data, f, indent=4)
        agent_logger.info("config.json updated successfully.")
    except Exception as e:
        agent_logger.error(f"Error saving config.json: {e}")

def get_hostname():
    return socket.gethostname()

def get_ip_address():
    try:
        # Create a temporary socket to determine default interface IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

def get_file_sha256(file_path):
    if not os.path.exists(file_path) or os.path.isdir(file_path):
        return None
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        agent_logger.debug(f"Could not hash file {file_path}: {e}")
        return None
