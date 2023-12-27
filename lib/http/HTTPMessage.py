from .HTTPStatus import HTTPStatus
from lib import utils


def parse_headers(fp):
    """ Parse the header except to a dict """
    headers = {}

    while True:
        line = fp.readline(1024)
        # Header will end with \r\n
        if line in (b'\r\n', b'\n', b''):
            break
        
        # split by `: `
        k, v = tuple(str(line, 'iso-8859-1').strip('\r\n').split(": ", maxsplit=1))
        headers[k.lower()] = v
    
    return headers


class Request:
    """ Request from client """

    def __init__(self):
        self.cmd = None
        self.path = None
        self.simple_path = None
        self.query = None
        self.headers = {}
        self.cookie = None
        self.auth = None
    
    def get_header(self, k):
        return self.headers.get(k.lower())

class Response:
    """ Response to client """
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
        self.add_header("Date", utils.formatdate(usegmt=True))
    
    def add_header(self, k, v):
        self.headers[k.lower()] = v

    def remove_header(self, k):
        return self.headers.pop(k.lower(), None)

    def header_encode(self, header):
        return header.encode("latin-1", "strict")
    
    def error(self, status, msg=None):
        self.set_status_line(status, msg)
        self.add_header("Connection", "close") # TODO: default to close
        self.write_headers()
    
    
    def write_headers(self):
        """ Write header to buffer """
        buffer = [("%s %d %s\r\n" % (Response.HTTP_VERSION, self.status, self.msg))] + \
            [("%s: %s\r\n" % (k, v)) for k, v in self.headers.items()] + \
            ["\r\n"]
        self.stream.write(b"".join(map(self.header_encode, buffer)))
        
        self.headers.clear()
    