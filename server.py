import argparse
import mimetypes
import socket
import asyncio


def http_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow socket to reuse address
    server_socket.bind(('localhost', 8080))
    server_socket.listen(1)
    

if __name__ == "__main__":
    http_server()
        