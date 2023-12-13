import socket
import os

import argparse


def get_content_type(filepath):
    if filepath.endswith(".html"):
        return "text/html"
    if filepath.endswith(".css"):
        return "text/css"
    if filepath.endswith(".js"):
        return "application/javascript"
    if filepath.endswith(".png"):
        return "image/png"
    if filepath.endswith(".jpg") or filepath.endswith(".jpeg"):
        return "image/jpeg"
    return "text/plain"

def serve_file(filepath):
    if not os.path.isfile(filepath):
        return (b"HTTP/1.1 404 Not Found\r\n"
                b"Content-Type: text/html\r\n\r\n"
                b"<html><body><h1>404 Not Found</h1></body></html>")

    with open(filepath, 'rb') as f:
        content = f.read()

    response_line = b"HTTP/1.1 200 OK\r\n"
    headers = b"Content-Type: " + get_content_type(filepath).encode() + b"\r\n"
    blank_line = b"\r\n"

    return response_line + headers + blank_line + content

def http_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow socket to reuse address
    server_socket.bind(('localhost', 8080))
    server_socket.listen(1)

    print("HTTP server running on port 8080...")


    while True:
        client_connection, client_address = server_socket.accept()
        keep_connection_open = True

        while keep_connection_open:
            request = client_connection.recv(1024).decode()
            if not request:
                # No request received, close connection
                break

            # Extract the filepath and headers from the received HTTP request
            headers = request.split('\r\n')
            filepath = headers[0].split(' ')[1]
            if filepath == '/':
                filepath = '/index.html'

            # Check if the connection should be closed after this request
            keep_connection_open = not any("Connection: close" in header for header in headers)

            response = serve_file(filepath.strip('/'))
            client_connection.sendall(response)

            if not keep_connection_open:
                print("close close")
                client_connection.close()


if __name__ == '__main__':
    http_server()
