import argparse
import threading
import time
from lib.server import HTTPRequestHandler, TCPServer

    

if __name__ == "__main__":
    try:
        http_server = TCPServer(("", 8080), HTTPRequestHandler)
        http_thread = threading.Thread(target=http_server.serve_forever)
        http_thread.daemon = True 
        http_thread.start()

        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        http_server.shutdown()
        print("Server close.")
        