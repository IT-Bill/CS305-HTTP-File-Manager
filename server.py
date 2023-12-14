import argparse
import asyncio
import threading
import time
from TCPServer import TCPServer
from handler.HTTPRequestHandler import HTTPRequestHandler
from handler.AuthHandler import AuthHandler

    

if __name__ == "__main__":
    try:
        http_server = TCPServer(("", 8000), HTTPRequestHandler)
        http_thread = threading.Thread(target=http_server.serve_forever)
        http_thread.daemon = True 
        http_thread.start()

        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        http_server.shutdown()
        print("Server close.")
        