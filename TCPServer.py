import socket
import selectors
import threading

if hasattr(selectors, 'PollSelector'):
    _ServerSelector = selectors.PollSelector
else:
    _ServerSelector = selectors.SelectSelector

class TCPServer:
    address_family = socket.AF_INET
    socket_type = socket.SOCK_STREAM

    request_queue_size = 5

    def __init__(self, server_address, RequestHandlerClass):
        self.server_address = server_address
        self.RequestHandlerClass = RequestHandlerClass
        self.__is_shut_down = threading.Event()
        self.__shutdown_request = False
        self.socket = socket.socket(self.address_family, self.socket_type)
        try:
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
                selector.register(self, selector.EVENT_READ)

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
                # call the RequestHandlerClass
                self.RequestHandlerClass(request, client_address, self)
            except Exception:
                # TODO
                request.close()
        
        except:
            request.close()
    
