from lib.http import HTTPStatus, HTTPMessage
from lib import utils
import lib

import urllib, pathlib, posixpath, mimetypes, threading
import os, io, sys, shutil
import base64, uuid
import traceback


class HTTPRequestHandler:
    def __init__(self, request, client_address, server):
        self.request = request
        self.client_address = client_address
        self.server = server
        self._headers_buffer = None

        # self.headers: HTTPMessage = None
        self.directory = os.path.join(os.getcwd(), "data")

        self.setup()

        try:
            self.handle()
        except:
            traceback.print_exc()
        finally:
            self.finish()

    def setup(self):
        """Setup the request socket"""
        self._headers_buffer = []
        self.rfile = self.request.makefile("rb", -1)
        self.wfile = _SocketWriter(self.request)

    def is_unauthorized(self):
        """
        Varify the authorization.
        """

        # TODO: elegent
        if self.headers["authorization"] != "":
            key = self.headers["authorization"].split(maxsplit=1)[1]
            if key in lib.keys:
                self.user = (
                    base64.b64decode(key).decode("utf-8").split(":", maxsplit=1)[0]
                )
                return False

        # send UNAUTHORIZED header
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("WWW-Authenticate", 'Basic realm="Test"')
        self.send_header("Content-type", "text\html")
        self.end_headers()
        self.close_connection = True
        return True

    def is_forbidden(self):
        """
        Check whether the path is forbidden.

        Redirect if user visites the root.
        """
        if self.command == "GET":
            segments = [
                seg
                for seg in posixpath.normpath(
                    urllib.parse.unquote(self.path.split("?", 1)[0].split("#", 1)[0])
                ).split("/")
                if seg
            ]
            if len(segments) == 0:
                # Visit the root directory of data, redirect.
                self.redirect(utils.join_path_query(os.path.join(self.user, ""), {"SUSTech-HTTP": "0"}))
                return True

            if segments[0] == self.user:
                return False
        
        elif self.command == "POST":
            # check the self.query["path"]
            segments = [
                seg
                for seg in posixpath.normpath(
                    urllib.parse.unquote(self.query["path"][0])
                ).split("/")
                if seg
            ]

            if len(segments) > 0 and segments[0] == self.user:
                return False

        self.send_error(HTTPStatus.FORBIDDEN)    
        return True

    def handle(self):
        """Handle the http request"""
        self.close_connection = False
        print(threading.current_thread().name)
        self.handle_one_request()
        while not self.close_connection:
            self.handle_one_request()

    def handle_one_request(self):
        """Handle a single HTTP request"""
        # `readline` is used to read one line of request message
        start_line = str(self.rfile.readline(1024), "iso-8859-1").rstrip("\r\n")
        print(start_line)
        # GET /path HTTP/1.1
        self.command, self.path, _ = start_line.split()
        if self.path.startswith("//"):
            self.path = "/" + self.path.lstrip("/")
        if self.path.endswith("//"):
            self.path = self.path.rstrip("/") + "/"
        
        self.simple_path, self.query = utils.parse_url(self.path)

        # parse header
        self.headers = HTTPMessage.parse_headers(self.rfile)

        # invoke the corresponding method
        method = getattr(self, f"do_{self.command}")
        method()
        # actually send the response
        self.wfile.flush()
    
    def do_GET(self):
        """Serve a GET request"""
        if self.is_unauthorized() or self.is_forbidden() or self.is_bad_request():
            return
        else:
            f = self.send_head()
            if f:
                try:
                    shutil.copyfileobj(f, self.wfile)
                finally:
                    f.close()

    def do_POST(self):
        """ Serve a POST request """
        if self.is_unauthorized() or self.is_bad_request() or self.is_forbidden():
            return
        
        if self.post_cmd == "upload":
            self.upload()
        elif self.post_cmd == "delete":
            self.delete()


    def do_HEAD(self):
        """Serve a HEAD request"""
        f = self.send_head()
        if f:
            f.close()
    
    def delete(self):
        path = self.path2local(self.query["path"][0])
        if not os.path.isfile(path):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        try:
            os.remove(path)
            self.send_response(HTTPStatus.OK)
            self.end_headers()
        except OSError:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
    
    def upload(self):
        path = self.path2local(self.query["path"][0])
        
        if not os.path.isdir(path):
            # the directory does not exist
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        
        content_length = int(self.headers['Content-Length'])
        file_data = self.rfile.read(content_length)
        file_name = utils.get_filename_from_content_disposition(self.headers['Content-Disposition'])
        if file_name is None:
            file_name = str(uuid.uuid1())
        file_path = os.path.join(path, file_name)
        with open(file_path, 'wb') as file:
            file.write(file_data)
        
        self.send_response(HTTPStatus.OK)
        self.end_headers()

    def is_bad_request(self):
        if self.command == "GET":
            # check SUSTech-HTTP query
            # not dir
            if not os.path.isdir(self.path2local(self.path)) or \
                len(self.query) == 1 and \
                self.query.get("SUSTech-HTTP") != None and \
                len(self.query["SUSTech-HTTP"]) == 1 and \
                self.query["SUSTech-HTTP"][0] in ("0", "1"):
                return False  # correct
            
        elif self.command == "POST":
            segments = [
                seg
                for seg in posixpath.normpath(
                    urllib.parse.unquote(self.simple_path)
                ).split("/")
                if seg
            ]
            if len(segments) == 1 and segments[0] in ["upload", "delete"]:
                if len(self.query) == 1 and \
                    self.query.get("path") != None and \
                    len(self.query["path"]) == 1:

                    # Recode the post command
                    self.post_cmd = segments[0]
                    return False
        
        self.send_error(HTTPStatus.BAD_REQUEST)
        return True


    def redirect(self, new_url, status=HTTPStatus.TEMPORARY_REDIRECT):
        """Redirect to new url."""
        self.send_response(status)
        self.send_header("Location", new_url)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def send_head(self):
        path = self.path2local(self.path)
        f = None
        if os.path.isdir(path):
            parts = urllib.parse.urlsplit(self.path)
            if not parts.path.endswith("/"):
                # Example: Redirect `/dir` to `/dir/`
                new_parts = (parts[0], parts[1], parts[2] + "/", parts[3], parts[4])
                new_url = urllib.parse.urlunsplit(new_parts)
                self.redirect(new_url, HTTPStatus.PERMANENT_REDIRECT)
                return None
            for index in "index.html", "index.htm":
                index = os.path.join(path, index)
                if os.path.exists(index):
                    path = index
                    break
            else:
                return self.list_directory(path)
        ctype, _ = mimetypes.guess_type(path)

        # parseing and rejection of filenames with a trailing slash
        if path.endswith("/"):
            self.send_error(HTTPStatus.NOT_FOUND)
            return None
        try:
            f = open(path, "rb")
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND)
            return None

        try:
            fs = os.fstat(f.fileno())
            # TODO: use browser cache

            self.send_response(HTTPStatus.OK)
            self.send_header("Content-type", ctype)
            self.send_header("Content-Length", fs.st_size)
            self.send_header("Last-Modified", utils.formatdate(fs.st_mtime))
            self.end_headers()
            return f
        except:
            f.close()
            raise


    def send_error(self, code):
        self.send_response(code, HTTPStatus(code).phrase)
        self.send_header("Connection", "close")
        self.end_headers()

    def list_directory(self, path):
        """Helper to produce a directory listing (absent index.html).

        Return value is either a file object, or None (indicating an
        error).  In either case, the headers are sent, making the
        interface the same as for send_head().

        """
        try:
            list = os.listdir(path)
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND)
            return None
        
        # already pass the query checking
        mode = self.query["SUSTech-HTTP"][0]
        list.sort(key=lambda a: a.lower())
        enc = sys.getfilesystemencoding()


        if mode == "1":
            display_list = []
            for name in list:
                fullname = os.path.join(path, name)
                displayname = name
                if os.path.isdir(fullname):
                    displayname = name + "/"
                display_list.append(displayname)
            
            encoded = str(display_list).encode(enc)
            
        elif mode == "0":
            r = []
            displaypath = utils.html_escape(self.simple_path, quote=False)
            title = "Directory listing for %s" % displaypath
            r.append("<!DOCTYPE>")
            r.append("<html>\n<head>")
            r.append(
                '<meta http-equiv="Content-Type" ' 'content="text/html; charset=%s">' % enc
            )
            r.append("<title>%s</title>\n</head>" % title)
            r.append("<body>\n<h1>%s</h1>" % title)
            r.append("<hr>\n<ul>")

            # add user root directory
            r.append(
                '<li><a href="%s">%s</a></li>'
                % (utils.join_path_query(os.path.join("/", self.user, ""), self.query), "/")
            )
            # add previous directory
            r.append(
                '<li><a href="%s">%s</a></li>'
                % (utils.join_path_query(os.path.join(str(pathlib.Path(self.path).parent), ""), self.query), "../")
            )
            for name in list:
                fullname = os.path.join(path, name)
                displayname = linkname = name
                if os.path.isdir(fullname):
                    displayname = name + "/"
                    linkname = utils.join_path_query(urllib.parse.quote(name + "/"), self.query)
                else:  
                    # file
                    linkname = urllib.parse.quote(name)
                
                r.append(
                    '<li><a href="%s">%s</a></li>'
                    % (linkname, utils.html_escape(displayname, quote=False))
                )

            r.append("</ul>\n<hr>\n</body>\n</html>\n")
            encoded = "\n".join(r).encode(enc)
        
        f = io.BytesIO()
        f.write(encoded)
        f.seek(0)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-type", "text/html; charset=%s" % enc)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        return f

    def path2local(self, path):
        """
        Convert an HTTP path to a local file system equivalent.
        Example:
            current work directory is /root/CS305/
            GET /12110817 -> /root/CS305/12110817
        """
        # Extracting the base path, excluding any query or fragment
        base_path = path.split("?", 1)[0].split("#", 1)[0]
        # Checking for and preserving a trailing slash
        ends_with_slash = base_path[-1] == "/" if base_path else False
        # Decoding any percent-encoded characters
        decoded_path = urllib.parse.unquote(base_path)
        # Standardizing the path
        standardized_path = posixpath.normpath(decoded_path)
        segments = [seg for seg in standardized_path.split("/") if seg]

        final_path = self.directory
        for part in segments:
            if not os.path.dirname(part) and part not in (os.curdir, os.pardir):
                final_path = os.path.join(final_path, part)
        # Adding back the trailing slash if it was present
        if ends_with_slash:
            final_path += "/"
        return final_path

    def send_response(self, status, msg=None):
        """Send the response header only"""
        if msg is None:
            msg = HTTPStatus(status).phrase
        self._headers_buffer.append(
            ("%s %d %s\r\n" % ("HTTP/1.1", status, msg)).encode("latin-1", "strict")
        )
        self.send_header("Date", utils.formatdate(usegmt=True))

    def send_header(self, k, v):
        """Add a header to the headers buffer"""
        self._headers_buffer.append(("%s: %s\r\n" % (k, v)).encode("latin-1", "strict"))
        if k.lower() == "connection":
            if v.lower() == "close":
                self.close_connection = True
            elif v.lower() == "keep-alive":
                self.close_connection = False

    def end_headers(self):
        self._headers_buffer.append(b"\r\n")
        # send the headers by invoke `write`
        self.wfile.write(b"".join(self._headers_buffer))
        self._headers_buffer = []

    def finish(self):
        """ """
        pass

class _SocketWriter(io.BufferedIOBase):
    """Simple writable BufferedIOBase implementation for a socket

    Does not hold data in a buffer, avoiding any need to call flush()."""

    def __init__(self, sock):
        self._sock = sock

    def writable(self):
        return True

    def write(self, b):
        if isinstance(b, str):
            b = b.encode("utf-8")

        self._sock.sendall(b)
        with memoryview(b) as view:
            return view.nbytes

    def fileno(self):
        return self._sock.fileno()
