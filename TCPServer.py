import socket
import selectors
import threading
import traceback

if hasattr(selectors, 'PollSelector'):
    _ServerSelector = selectors.PollSelector
else:
    _ServerSelector = selectors.SelectSelector

class TCPServer:

    request_queue_size = 5

    def __init__(self, server_address, RequestHandlerClass):
        self.server_address = server_address
        self.RequestHandlerClass = RequestHandlerClass
        self.__is_shut_down = threading.Event()
        self.__shutdown_request = False
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # allow_reuse_address
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(self.server_address)
            self.server_address = self.socket.getsockname()
            self.socket.listen(self.request_queue_size)
        except:
            self.socket.close()
    
    def serve_forever(self, poll_interval=0.5):
        self.__is_shut_down.clear()
        try:
            with _ServerSelector() as selector:
                selector.register(self.socket, selectors.EVENT_READ)

                while not self.__shutdown_request:
                    ready = selector.select(poll_interval)
                    if self.__shutdown_request:
                        break
                    if ready:
                        self._handle_request()
        finally:
            self.__shutdown_request = False
            self.__is_shut_down.set()

    def _handle_request(self):
        try:
            request, client_address = self.socket.accept()
            try:
                # call the RequestHandlerClass use different threads
                handler = threading.Thread(target=self.RequestHandlerClass, args=(request, client_address, self))
                handler.daemon = True
                handler.start()
            except Exception:
                # TODO
                if request:
                    request.close()
        
        except:
            if request:
                request.close()
    
    def shutdown(self):
        """ Stop the serve_forever loop """
        self.__shutdown_request = True 
        self.__is_shut_down.wait()
