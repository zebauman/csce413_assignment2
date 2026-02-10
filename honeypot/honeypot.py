#!/usr/bin/env python3
"""Starter template for the honeypot assignment."""

import logging
import socket
import threading
import time
import os
import paramiko
import sys
import json
import datetime

# CONFIGURATION
LOG_PATH = "logs/honeypot.log" 
JSON_LOG_PATH = "logs/connections.jsonl"
HOST_KEY_PATH = "host.key"
BIND_IP = "0.0.0.0"
BIND_PORT = 2222

# SETUP LOGGING
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler(sys.stdout)
    ],
)
logger = logging.getLogger("SSH-Honeypot")

# GENERATE HOST KEY IF MISSING
if not os.path.exists(HOST_KEY_PATH):
    logger.info("Generating new host key...")
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_PATH)
HOST_KEY = paramiko.RSAKey(filename=HOST_KEY_PATH)


def log_json_connection(ip, port):
    """Writes the connection event to a JSONL file."""
    event = {
        "timestamp": datetime.datetime.now().isoformat(),
        "event": "connection",
        "client_ip": ip,
        "client_port": port
    }
    with open(JSON_LOG_PATH, "a") as f:
        f.write(json.dumps(event) + "\n")

class HoneypotServer(paramiko.ServerInterface):
    """
    Paramiko Server Interface to handle SSH events.
    """
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # LOG THE ATTACKER'S CREDENTIALS
        logger.info(f"LOGIN ATTEMPT - IP: {self.client_ip} | User: {username} | Pass: {password}")
        
        # ACTUALLY LET THEM IN To capture commands        
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


def handle_connection(client_sock, client_addr):
    """Handle a single connection."""
    ip, port = client_addr
    logger.info(f"CONNECTION DETECTED from {ip}")
    log_json_connection(ip, port)

    transport = paramiko.Transport(client_sock)
    transport.add_server_key(HOST_KEY)
    
    server = HoneypotServer(ip)
    
    try:
        transport.start_server(server=server)
    except (paramiko.SSHException, EOFError):
        logger.warning(f"SSH Negotiation failed or Client {ip} disconnected.")
        return
    except Exception as e:
        logger.error(f"Unexpected error during negotiation with {ip}: {e}")
        return

    # WAIT FOR AUTH.
    chan = transport.accept(20)
    if chan is None:
        logger.info(f"Connection closed by {ip} (No channel opened)")
        return

    server.event.wait(10)
    if not server.event.is_set():
        logger.info(f"Client {ip} never requested a shell.")
        chan.close()
        return

    # FAKE SHELL EMULATION
    chan.send("Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-144-generic x86_64)\r\n\r\n")
    chan.send("Last login: " + time.ctime() + " from 192.168.1.10\r\n")
    
    try:
        while True:
            chan.send("root@server:~# ")
            command = ""
            while True:
                char = chan.recv(1).decode('utf-8')
                
                # Handle Enter
                if char == '\r':
                    chan.send('\r\n')
                    break
                
                # Handle Backspace
                elif char == '\x7f': 
                    if len(command) > 0:
                        command = command[:-1]
                        chan.send('\b \b') # Erase character on terminal
                
                # Handle standard chars
                else:
                    command += char
                    chan.send(char)

            if command.strip() == "exit":
                chan.send("logout\r\n")
                break
                
            if command.strip():
                logger.info(f"COMMAND EXECUTED - IP: {ip} | Cmd: {command}")
                # Fake response to common commands
                if command.strip() == "ls":
                    chan.send("id_rsa  notes.txt  passwords.txt\r\n")
                elif command.strip() == "whoami":
                    chan.send("root\r\n")
                elif command.strip() == "pwd":
                    chan.send("/root\r\n")
                else:
                    chan.send(f"bash: {command}: command not found\r\n")

    except Exception as e:
        logger.error(f"Error handling session for {ip}: {e}")
    finally:
        chan.close()
        transport.close()
        logger.info(f"Connection closed for {ip}")


def run_honeypot():
    logger.info(f"Starting SSH Honeypot on port {BIND_PORT}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((BIND_IP, BIND_PORT))
    sock.listen(100)

    while True:
        try:
            client_sock, client_addr = sock.accept()
            t = threading.Thread(target=handle_connection, args=(client_sock, client_addr))
            t.start()
        except Exception as e:
            logger.error(f"Accept error: {e}")

if __name__ == "__main__":
    run_honeypot()