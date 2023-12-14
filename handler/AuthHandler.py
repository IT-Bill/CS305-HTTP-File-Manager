from handler.HTTPRequestHandler import HTTPRequestHandler
from lib import utils
from lib.http import HTTPStatus
import base64

key = base64.b64encode(b'test:test').decode()

class AuthHandler(HTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(HTTPStatus.OK)
        self.send_header('Content-type', 'text\html')
        self.end_headers()
    
    def do_AUTHHEAD(self):
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("WWW-Authenticate", 'Basic realm=\"Test\"')
        self.send_header('Content-type', 'text\html')
        self.end_headers()
    
    def do_GET(self):
        ''' Present frontpage with user authentication. '''
        global key
        
        if self.headers['authorization'] == 'Basic ' + key:
            HTTPRequestHandler.do_GET(self)
        else:
            self.do_AUTHHEAD()