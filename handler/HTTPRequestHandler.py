from io import BufferedIOBase
import urllib, os, posixpath, io
from lib.http import HTTPStatus
import mimetypes
from lib import html, utils
import sys
import traceback
import shutil
from lib.http.HTTPMessage import HTTPMessage
import base64
import lib


class HTTPRequestHandler:
    def __init__(self, request, client_address, server, directory=None):
        self.request = request
        self.client_address = client_address
        self.server = server
        self._headers_buffer = None

        # self.headers: HTTPMessage = None

        if directory is None:
            directory = os.getcwd()
        self.directory = os.fspath(directory)
        
        self.setup()

        try:
            self.handle()
        except:
            traceback.print_exc()
        finally:
            self.finish()
    
    def setup(self):
        """ Setup the request socket """
        self._headers_buffer = []
        self.rfile = self.request.makefile("rb", -1)
        self.wfile = _SocketWriter(self.request)

    def is_authorized(self):
        """ Varify the authorization """
        
        # TODO: elegent
        if self.headers['authorization'] != "":
            key = self.headers['authorization'].split(maxsplit=1)[1]
            if key in lib.keys:
                user = base64.b64decode(key).decode('utf-8').split(":", maxsplit=1)[0]
                # self.directory = os.path.join(os.getcwd(), "data", user)
                return True
        return False 


    def handle(self):
        """ Handle the http request """
        self.close_connection = True # !

        self.handle_one_request()
        while not self.close_connection:
            self.handle_one_request()

    def handle_one_request(self):
        """ Handle a single HTTP request """
        # `readline` is used to read one line of request message
        start_line = str(self.rfile.readline(1024), 'iso-8859-1').rstrip('\r\n')
        print(start_line)
        # GET /path HTTP/1.1
        self.command, self.path, _ = start_line.split()
        if self.path.startswith("//"):
            self.path = '/' + self.path.lstrip('/')
        
        # parse header
        self.headers = HTTPMessage.parse_headers(self.rfile)

        # invoke the corresponding method
        method = getattr(self, f'do_{self.command}')
        method()
        # actually send the response
        self.wfile.flush()
    
    def do_GET(self):
        """ Serve a GET request """
        if not self.is_authorized():
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header("WWW-Authenticate", 'Basic realm=\"Test\"')
            self.send_header('Content-type', 'text\html')
            self.end_headers()
        else:
            f = self.send_head()
            if f:
                try:
                    shutil.copyfileobj(f, self.wfile)
                finally:
                    f.close()
                
    
    def do_POST(self):
        print("Do post")

    def do_HEAD(self):
        """ Serve a HEAD request """
        f = self.send_head()
        if f:
            f.close()

    def send_head(self):
        path = self.path2local(self.path)
        f = None
        if os.path.isdir(path):
            parts = urllib.parse.urlsplit(self.path)
            if not parts.path.endswith('/'):
                # redirect browser - doing basically what apache does
                self.send_response(HTTPStatus.MOVED_PERMANENTLY)
                new_parts = (parts[0], parts[1], parts[2] + '/',
                             parts[3], parts[4])
                new_url = urllib.parse.urlunsplit(new_parts)
                self.send_header("Location", new_url)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return None
            for index in "index.html", "index.htm":
                index = os.path.join(path, index)
                if os.path.exists(index):
                    path = index
                    break
            else:
                return self.list_directory(path)
        ctype = mimetypes.guess_type(path)

        # parseing and rejection of filenames with a trailing slash
        if path.endswith("/"):
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return None
        try:
            f = open(path, 'rb')
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return None
        
        try:
            fs = os.fstat(f.fileno())
            # TODO: use browser cache

            self.send_response(HTTPStatus.OK)
            self.send_header("Content-type", ctype)
            self.send_header("Content-Length", fs.st_size)
            self.send_header("Last-Modified",
                utils.formatdate(fs.st_mtime))
            self.end_headers()
            return f
        except:
            f.close()
            raise

    def list_directory(self, path):
        """Helper to produce a directory listing (absent index.html).

        Return value is either a file object, or None (indicating an
        error).  In either case, the headers are sent, making the
        interface the same as for send_head().

        """
        try:
            list = os.listdir(path)
        except OSError:
            self.send_error(
                HTTPStatus.NOT_FOUND,
                "No permission to list directory")
            return None
        list.sort(key=lambda a: a.lower())
        r = []
        try:
            displaypath = urllib.parse.unquote(self.path,
                                               errors='surrogatepass')
        except UnicodeDecodeError:
            displaypath = urllib.parse.unquote(path)
        displaypath = html.escape(displaypath, quote=False)
        enc = sys.getfilesystemencoding()
        title = 'Directory listing for %s' % displaypath
        r.append('<!DOCTYPE>')
        r.append('<html>\n<head>')
        r.append('<meta http-equiv="Content-Type" '
                 'content="text/html; charset=%s">' % enc)
        r.append('<title>%s</title>\n</head>' % title)
        r.append('<body>\n<h1>%s</h1>' % title)
        r.append('<hr>\n<ul>')
        for name in list:
            fullname = os.path.join(path, name)
            displayname = linkname = name
            # Append / for directories or @ for symbolic links
            if os.path.isdir(fullname):
                displayname = name + "/"
                linkname = name + "/"
            if os.path.islink(fullname):
                displayname = name + "@"
                # Note: a link to a directory displays with @ and links with /
            r.append('<li><a href="%s">%s</a></li>'
                    % (urllib.parse.quote(linkname,
                                          errors='surrogatepass'),
                       html.escape(displayname, quote=False)))
        r.append('</ul>\n<hr>\n</body>\n</html>\n')
        encoded = '\n'.join(r).encode(enc, 'surrogateescape')
        f = io.BytesIO()
        f.write(encoded)
        f.seek(0)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-type", "text/html; charset=%s" % enc)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        return f

    def path2local(self, path):
        """Convert an HTTP path to a local file system equivalent. """
        # Extracting the base path, excluding any query or fragment
        base_path = path.split('?', 1)[0].split('#', 1)[0]
        # Checking for and preserving a trailing slash
        ends_with_slash = base_path[-1] == '/' if base_path else False
        # Decoding any percent-encoded characters
        try:
            decoded_path = urllib.parse.unquote(base_path, errors='surrogatepass')
        except UnicodeDecodeError:
            decoded_path = urllib.parse.unquote(base_path)
        # Standardizing the path
        standardized_path = posixpath.normpath(decoded_path)
        segments = [seg for seg in standardized_path.split('/') if seg]
        final_path = self.directory
        for part in segments:
            if not os.path.dirname(part) and part not in (os.curdir, os.pardir):
                final_path = os.path.join(final_path, part)
        # Adding back the trailing slash if it was present
        if ends_with_slash:
            final_path += '/'
        return final_path
        

    def send_response(self, status, msg=None):
        """ Send the response header only """
        if msg is None:
            msg = HTTPStatus(status).phrase
        self._headers_buffer.append(("%s %d %s\r\n" %
                ("HTTP/1.1", status, msg)).encode(
                    'latin-1', 'strict'))
        self.send_header('Date', utils.formatdate(usegmt=True))
    
    def send_header(self, k, v):
        """ Add a header to the headers buffer """
        self._headers_buffer.append(
                ("%s: %s\r\n" % (k, v)).encode('latin-1', 'strict'))
        if k.lower() == 'connection':
            if v.lower() == 'close':
                self.close_connection = True
            elif v.lower() == 'keep-alive':
                self.close_connection = False
    
    def end_headers(self):
        self._headers_buffer.append(b'\r\n')
        # send the headers by invoke `write`
        self.wfile.write(b''.join(self._headers_buffer))
        self._headers_buffer = []

    def finish(self):
        """  """
        pass


class _SocketWriter(BufferedIOBase):
    """Simple writable BufferedIOBase implementation for a socket

    Does not hold data in a buffer, avoiding any need to call flush()."""

    def __init__(self, sock):
        self._sock = sock

    def writable(self):
        return True

    def write(self, b):
        if isinstance(b, str):
            b = b.encode('utf-8')
        
        self._sock.sendall(b)
        with memoryview(b) as view:
            return view.nbytes

    def fileno(self):
        return self._sock.fileno()