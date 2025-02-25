import logging
from logging.handlers import RotatingFileHandler
import socket
import paramiko
import threading
from datetime import datetime

# Constants
LOG_FORMAT = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
SSH_BANNER = "SSH-2.0-MySSHServer_1.0"

# Setup Logging
connection_logger = logging.getLogger('connectionLogger')
connection_logger.setLevel(logging.INFO)
conn_handler = RotatingFileHandler('connections.log', maxBytes=5000, backupCount=5)
conn_handler.setFormatter(LOG_FORMAT)
connection_logger.addHandler(conn_handler)

creds_logger = logging.getLogger('credsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler('credentials.log', maxBytes=5000, backupCount=5)
creds_handler.setFormatter(LOG_FORMAT)
creds_logger.addHandler(creds_handler)

cmd_logger = logging.getLogger('cmdLogger')
cmd_logger.setLevel(logging.INFO)
cmd_handler = RotatingFileHandler('commands.log', maxBytes=5000, backupCount=5)
cmd_handler.setFormatter(LOG_FORMAT)
cmd_logger.addHandler(cmd_handler)

# Console Logging
console_handler = logging.StreamHandler()
console_handler.setFormatter(LOG_FORMAT)
connection_logger.addHandler(console_handler)
creds_logger.addHandler(console_handler)
cmd_logger.addHandler(console_handler)

# Emulated Shell
def emulated_shell(channel, client_ip):
    channel.send(b'corporate-jumpbox2$ ')
    command = b""
    while True:
        char = channel.recv(1)
        if not char:
            break
        channel.send(char)
        command += char
        if char == b'\r':
            cmd_text = command.strip().decode()
            cmd_logger.info(f"{client_ip} executed: {cmd_text}")
            
            if cmd_text == 'exit':
                response = b'\nGoodbye!\n'
                channel.send(response)
                break
            elif cmd_text == 'pwd':
                response = b'\n/usr/local\r\n'
            elif cmd_text == 'whoami':
                response = b'\ncorpuser1\r\n'
            elif cmd_text == 'ls':
                response = b'\njumpbox1.conf\r\n'
            elif cmd_text == 'cat jumpbox1.conf':
                response = b'\nGo to deeboodah.com\r\n'
            else:
                response = b'\n' + command.strip() + b'\r\n'
            
            channel.send(response)
            channel.send(b'corporate-jumpbox2$ ')
            command = b""
    channel.close()

# SSH Server Class
class Server(paramiko.ServerInterface):
    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        creds_logger.info(f"Login attempt from {self.client_ip} - Username: {username}, Password: {password}")
        return paramiko.AUTH_SUCCESSFUL if (self.input_username is None or username == self.input_username) and (self.input_password is None or password == self.input_password) else paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

# Client Handling Function
def client_handle(client, addr, username, password):
    client_ip = addr[0]
    connection_logger.info(f"New connection from {client_ip}")
    
    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = Server(client_ip=client_ip, input_username=username, input_password=password)
        
        host_key = paramiko.RSAKey.generate(2048)
        transport.add_server_key(host_key)
        
        transport.start_server(server=server)
        
        channel = transport.accept(100)
        if channel is None:
            connection_logger.warning(f"No channel opened for {client_ip}")
            return
        
        standard_banner = "Welcome to Ubuntu 22.04 LTS (Jammy Jellyfish)!\r\n\r\n"
        channel.send(standard_banner.encode())
        emulated_shell(channel, client_ip=client_ip)
    except Exception as error:
        connection_logger.error(f"Error handling client {client_ip}: {error}")
    finally:
        try:
            transport.close()
        except Exception as error:
            connection_logger.error(f"Error closing transport for {client_ip}: {error}")
        client.close()
        connection_logger.info(f"Connection closed for {client_ip}")

# Provision SSH-based Honeypot
def honeypot(address, port, username, password):
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    socks.bind((address, port))
    socks.listen(100)
    connection_logger.info(f"SSH Honeypot listening on {address}:{port}")
    
    while True:
        try:
            client, addr = socks.accept()
            ssh_honeypot_thread = threading.Thread(target=client_handle, args=(client, addr, username, password))
            ssh_honeypot_thread.start()
        except Exception as error:
            connection_logger.error(f"Error accepting connection: {error}")

# Start Honeypot
honeypot('127.0.0.1', 2233, 'user', 'pass')
