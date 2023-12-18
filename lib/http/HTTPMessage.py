from .HTTPStatus import HTTPStatus
from lib import utils

class HTTPMessage:

    def __init__(self):
        self.headers = {}


    @staticmethod
    def parse_headers(fp):
        msg = HTTPMessage()
        
        while True:
            line = fp.readline(1024)
            if line in (b'\r\n', b'\n', b''):
                break
            
            # split by `: `
            k, v = tuple(str(line, 'iso-8859-1').strip('\r\n').split(": ", maxsplit=1))
            msg.headers[k.lower()] = v
        
        return msg
    
    def __getitem__(self, k):
        return self.headers.get(k.lower(), "")

class Request:
    """  """

    def __init__(self):
        pass

class Response:
    """  """
    HTTP_VERSION = "HTTP/1.1"

    def __init__(self, stream=None):
        self.status = None
        self.msg = None

        self.headers = {}

        self.content = None

        self.cookies = None

        self.stream = stream
    
    def set_status_line(self, status, msg=None):
        self.status = status
        self.msg = msg if msg else HTTPStatus(status).phrase
        self.set_header("Date", utils.formatdate(usegmt=True))
    
    def set_header(self, k, v):
        self.headers[k] = v

    def header_encode(self, header):
        return header.encode("latin-1", "strict")
    
    def error(self, status, msg=None):
        self.set_status_line(status, msg)
        self.set_header("Connection", "close")
        self.write_headers()
    
    def write_headers(self):
        buffer = [("%s %d %s\r\n" % (Response.HTTP_VERSION, self.status, self.msg))] + \
            [("%s: %s\r\n" % (k, v)) for k, v in self.headers.items()] + \
            ["\r\n"]
        self.stream.write(b"".join(map(self.header_encode, buffer)))
        
        self.headers.clear()