from lib.http import HTTPStatus, HTTPMessage
from lib import utils
import lib
from lib.http.HTTPMessage import Response, Request
from lib.http.cookiejar import CookieJar
from lib.http.auth import BasicAuth

import urllib, pathlib, posixpath, mimetypes, threading
import os, io, sys, shutil
import base64, uuid
import traceback


class HTTPRequestHandler:
    def __init__(self, request, client_address, server):
        self.request = request
        self.client_address = client_address
        self.server = server

        self.directory = os.path.join(os.getcwd(), "data")

        self.use_cookie = False

        self.rfile = self.request.makefile("rb", -1)
        self.setup()

        try:
            self.handle()
        except:
            traceback.print_exc()
        finally:
            self.finish()

    def setup(self):
        """Setup the request socket"""
        self.wfile = _SocketWriter(self.request)

        self._request = Request()
        self._response = Response(self.wfile)

    def handle(self):
        """Handle the http request"""
        self.close_connection = False

        self.handle_one_request()
        while not self.close_connection:
            self.setup()
            self.handle_one_request()

    def handle_one_request(self):
        """Handle a single HTTP request"""
        # `readline` is used to read one line of request message
        start_line = str(self.rfile.readline(65537), "iso-8859-1").rstrip("\r\n")
        if not start_line:
            print("Empty command line")
            self.close_connection = True
            return
        
        # GET /path HTTP/1.1
        command, path, _ = start_line.split()
        path = urllib.parse.unquote(path) # Prevent wrong quote in Windowns
        path = path.replace("\\", "/")
        print(command, path, _)

        if path.startswith("//"):
            path = "/" + path.lstrip("/")
        if path.endswith("//"):
            path = path.rstrip("/") + "/"

        self._request.cmd, self._request.path = command, path
        self._request.simple_path, self._request.query = utils.parse_url(
            self._request.path
        )
        # parse header
        self._request.headers = HTTPMessage.parse_headers(self.rfile)

        # invoke the corresponding method
        method = getattr(self, f"do_{self._request.cmd}")
        method()
        # actually send the response
        self.wfile.flush()

        conn = self._request.get_header("Connection")
        if conn and conn == "close":
            self.close_connection = True

    def send_chunked_response(self, f):
        """Send data in chunks for chunked transfer encoding."""
        while True:
            chunk = f.read(8192)
            if not chunk:
                break

            self.wfile.write(f"{len(chunk):X}\r\n".encode())
            self.wfile.write(chunk)
            self.wfile.write(b"\r\n")

        self.wfile.write(b"0\r\n\r\n")

    def do_GET(self):
        """Serve a GET request"""
        if self._request.path != "/favicon.ico" and self._request.path != "/login.html" and self._request.path != "/login" and (
            self.is_unauthorized() or self.is_forbidden() or self.is_bad_request()
        ):
            return
        elif self._request.path in ["/login.html", "/login"]:
            self.serve_html_file('lib/templates/login.html')
        else:
            f = self.send_head()
            if f:
                try:
                    # chunked transfer
                    if self._request.query.get("chunked") == ["1"]:
                        self._response.add_header("Transfer-Encoding", "chunked")
                        self._response.remove_header("Content-Length")
                        self._response.write_headers()
                        self.send_chunked_response(f)
                    else:
                        # breakpoint transmission
                        range_header = self._request.get_header('Range')
                        # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                        self._response.remove_header("Content-Length")  # !!!!!!
                        # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                        if range_header:
                            ranges = [tuple(map(int, r.split('-'))) for r in range_header[range_header.index('bytes=') + 6:].split(',')]
                            file_size = os.path.getsize(f.name)
                            if all(0 <= start <= end < file_size for start, end in ranges):
                                boundary = '3d6b6a416f9b5'
                                self._response.add_header('Content-Type', f'multipart/byteranges; boundary={boundary}')
                                # Partial Content
                                self._response.set_status_line(HTTPStatus.PARTIAL_CONTENT) 
                                self._response.write_headers()
                                for range_start, range_end in ranges:
                                    f.seek(range_start)
                                    self.wfile.write(f'--{boundary}\r\n')
                                    self.wfile.write(f'Content-Type: {mimetypes.guess_type(f.name)[0]}\r\n')
                                    self.wfile.write(f'Content-Range: bytes {range_start}-{range_end}/{file_size}\r\n\r\n')
                                    # shutil.copyfileobj(f, self.wfile, range_end - range_start + 1)
                                    self.wfile.write(f.read(range_end - range_start + 1))
                                    self.wfile.write('\r\n')
                                self.wfile.write(f'--{boundary}--\r\n')
                            else:
                                # Range Not Satisfiable
                                self._response.set_status_line(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
                                self._response.write_headers()
                        else:
                            self._response.write_headers()
                            shutil.copyfileobj(f, self.wfile)
                finally:
                    f.close()

    def handle_post_request(self):
        # 此方法应在接收到 POST 请求时被调用
        # 获取内容长度
        #AttributeError: 'socket' object has no attribute 'headers'

        content_length = int(self._request.get_header('Content-Length'))

        # 读取 payload
        payload = self.rfile.read(content_length).decode('utf-8')

        # 处理 payload
        # 例如，可以解析为 key-value 形式，或处理 JSON 数据等
        # 这里的处理方式取决于 payload 的具体格式和您的需求

        # 示例：打印 payload
        return payload

        # 根据需要添加其他处理逻辑
        # ...

# 在处理请求的地方调用 handle_post_request
# 例如，在某个方法中根据请求类型来决定调用哪个处理方法
# if request.method == 'POST':
#     handler.handle_post_request()

    def serve_html_file(self, file_name):
        """Serve a html file"""
        path = os.path.join(os.getcwd(), file_name)
        if not os.path.isfile(path):
            self.response_error(HTTPStatus.NOT_FOUND)
            return
        try:
            f = open(path, "rb")
            self._response.set_status_line(HTTPStatus.OK)
            self._response.add_header("Content-type", "text/html")
            self._response.add_header("Content-Length", os.path.getsize(path))
            self._response.write_headers()
            shutil.copyfileobj(f, self.wfile)
        except OSError:
            self.response_error(HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self):
        """Serve a POST request"""
        if self._request.path in ["/login", "/login.html"]:
            #从payload中获取用户名和密码
            payload = self.handle_post_request()
            #按照&分割
            payload = payload.split('&')
            username = payload[0].split('=')[1]
            password = payload[1].split('=')[1]
            # print(password)
            #验证用户名和密码
            if self.is_unauthorized(username, password):
                #给浏览器弹窗
                self.serve_html_file('lib/templates/login.html')
            else:
                #重定向到主页
                print(self._request.auth.username)
                self.redirect(
                    utils.join_path_query(
                        os.path.join("/", self._request.auth.username, ""),
                        {"SUSTech-HTTP": "1"},
                    )
                )
            return

            # username = payload.get("username")
            # print(username)
            # password = payload.get("password")
            # print(password)
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

    def send_head(self):
        path = self.path2local(self._request.path)
        f = None
        if os.path.isdir(path):
            parts = urllib.parse.urlsplit(self._request.path)
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

        # isfile
        ctype, _ = mimetypes.guess_type(path)

        # parseing and rejection of filenames with a trailing slash
        if path.endswith("/"):
            self.response_error(HTTPStatus.NOT_FOUND)
            return None

        try:
            if self._request.path == "/favicon.ico":
                f = open(os.path.join(os.getcwd(), "favicon.ico"), "rb")
            else:
                f = open(path, "rb")
        except OSError:
            self.response_error(HTTPStatus.NOT_FOUND)
            return None

        try:
            fs = os.fstat(f.fileno())
            # TODO: use browser cache

            self._response.set_status_line(HTTPStatus.OK)
            self._response.add_header("Content-type", ctype)
            self._response.add_header("Content-Length", fs.st_size)
            self._response.add_header("Last-Modified", utils.formatdate(fs.st_mtime))
            # self._response.write_headers()
            return f
        except:
            f.close()
            raise

    def delete(self):
        path = self.path2local(self._request.query["path"][0])
        if not os.path.isfile(path):
            self.response_error(HTTPStatus.NOT_FOUND)
            return
        try:
            os.remove(path)
            self._response.set_status_line(HTTPStatus.OK)
            self._response.write_headers()

        except OSError:
            self.response_error(HTTPStatus.INTERNAL_SERVER_ERROR)

    def upload(self):
        path = self.path2local(self._request.query["path"][0])

        if not os.path.isdir(path):
            # the directory does not exist
            self.response_error(HTTPStatus.NOT_FOUND)
            return

        content_length = int(self._request.get_header("Content-Length"))
        file_data = self.rfile.read(content_length)
        file_name = utils.get_filename_from_content_disposition(
            self._request.get_header("Content-Disposition")
        )
        if file_name is None:
            file_name = str(uuid.uuid1())
        file_path = os.path.join(path, file_name)
        with open(file_path, "wb") as file:
            file.write(file_data)

        self._response.set_status_line(HTTPStatus.OK)
        self._response.write_headers()

    def is_bad_request(self):
        if self._request.cmd == "GET":
            # check SUSTech-HTTP query
            # not dir
            if (
                os.path.isfile(self.path2local(self._request.path))
                or self._request.query.get("SUSTech-HTTP")
                and self._request.query["SUSTech-HTTP"] in (["0"], ["1"])
            ):
                return False  # correct

        elif self._request.cmd == "POST":
            segments = [
                seg
                for seg in posixpath.normpath(
                    urllib.parse.unquote(self._request.simple_path)
                ).split("/")
                if seg
            ]
            if len(segments) == 1 and segments[0] in ["upload", "delete"]:
                if (
                    self._request.query.get("path") != None
                    and len(self._request.query["path"]) == 1
                ):
                    # Recode the post command
                    self.post_cmd = segments[0]
                    return False

        self.response_error(HTTPStatus.BAD_REQUEST)
        return True

    def is_unauthorized(self,username=None,password=None):
        """
        Varify the authorization.
        """
        def set_unauthorized_response():
            self._response.set_status_line(HTTPStatus.UNAUTHORIZED)
            self._response.add_header("WWW-Authenticate", 'Basic realm="Test"')
            self._response.add_header("Content-type", "text\html")
            self._response.write_headers()
            self.close_connection = True
        if username != None and password != None:
            auth = BasicAuth(username,password)
            if auth and auth.valid:
                self._request.auth = auth
                self._response.add_header(
                    "Set-Cookie", str(CookieJar.generate_cookie(auth.username))
                )
                return False
            else:
                return True


        # if self.use_cookie:
        #     cookie = CookieJar.from_cookie_header(self._request.get_header("Cookie"))
        #     if cookie and cookie.valid:
        #         self._request.cookie = cookie
        #         return False
            
        #     self.use_cookie = False
        #     set_unauthorized_response()
        #     return True

        auth = BasicAuth.from_auth_header(self._request.get_header("authorization"))
        if auth and auth.valid:
            self._request.auth = auth
            self._response.add_header(
                "Set-Cookie", str(CookieJar.generate_cookie(auth.username))
            )

            # TODO: redirect when different user logins

            # self.use_cookie = True
            return False

        # send UNAUTHORIZED header
        set_unauthorized_response()
        return True



    def is_forbidden(self):
        """
        Check whether the path is forbidden.

        Redirect if user visites the root.
        """
        if self._request.cmd == "GET":
            segments = [
                seg
                for seg in posixpath.normpath(
                    urllib.parse.unquote(
                        self._request.path.split("?", 1)[0].split("#", 1)[0]
                    )
                ).split("/")
                if seg
            ]
            if len(segments) == 0:
                # Visit the root directory of data, redirect.
                self.redirect(
                    utils.join_path_query(
                        os.path.join(self._request.auth.username, ""),
                        {"SUSTech-HTTP": "1"},
                    )
                )
                return True

            if segments[0] == self._request.auth.username:
                return False

        elif self._request.cmd == "POST":
            # check the self._request.query["path"]
            segments = [
                seg
                for seg in posixpath.normpath(
                    urllib.parse.unquote(self._request.query["path"][0])
                ).split("/")
                if seg
            ]

            if len(segments) > 0 and segments[0] == self._request.auth.username:
                return False

        self.response_error(HTTPStatus.FORBIDDEN)
        return True

    def redirect(self, new_url, status=HTTPStatus.SEE_OTHER):
        """Redirect to new url."""
        #让浏览器从response里面，得到下次发get请求、访问的url
        self._response.set_status_line(status)
        self._response.add_header("Location", new_url)
        self._response.add_header("Content-Length", "0")
        self._response.write_headers()

    def list_directory(self, path):
        """Helper to produce a directory listing (absent index.html).

        Return value is either a file object, or None (indicating an
        error).  In either case, the headers are sent, making the
        interface the same as for send_head().

        """
        try:
            list = os.listdir(path)
        except OSError:
            self.response_error(HTTPStatus.NOT_FOUND)
            return None

        # already pass the query checking
        mode = self._request.query["SUSTech-HTTP"][0]
        list.sort(key=lambda a: a.lower())
        enc = sys.getfilesystemencoding()

        if mode == "":
            display_list = []
            for name in list:
                fullname = os.path.join(path, name)
                displayname = name
                if os.path.isdir(fullname):
                    displayname = name + "/"
                display_list.append(displayname)

            encoded = str(display_list).encode(enc)
            
        elif mode == "1":
            r = []
            displaypath = utils.html_escape(self._request.simple_path, quote=False)
            title = "Directory listing for %s" % displaypath
            r.append("<!DOCTYPE>")
            r.append("<html>\n<head>")
            r.append(
                '<meta http-equiv="Content-Type" '
                'content="text/html; charset=%s">' % enc
            )
            r.append("<title>%s</title>\n</head>" % title)
            r.append("<body>\n<h1>%s</h1>" % title)
            r.append("<hr>\n<ul>")

            # add user root directory
            r.append(
                '<li><a href="%s">%s</a></li>'
                % (
                    utils.join_path_query(
                        os.path.join("/", self._request.auth.username, ""),
                        self._request.query,
                    ),
                    "/",
                )
            )
            # add previous directory
            r.append(
                '<li><a href="%s">%s</a></li>'
                % (
                    utils.join_path_query(
                        os.path.join(str(pathlib.Path(self._request.path).parent), ""),
                        self._request.query,
                    ),
                    "../",
                )
            )
            for name in list:
                fullname = os.path.join(path, name)
                displayname = linkname = name
                if os.path.isdir(fullname):
                    displayname = name + "/"
                    linkname = utils.join_path_query(
                        urllib.parse.quote(name + "/"), self._request.query
                    )
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
        self._response.set_status_line(HTTPStatus.OK)
        self._response.add_header("Content-type", "text/html; charset=%s" % enc)
        self._response.add_header("Content-Length", str(len(encoded)))
        # self._response.write_headers()
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

    def response_error(self, status, msg=None):
        self._response.error(status, msg)
        self.close_connection = True

    def finish(self):
        """ """


class _SocketWriter(io.BufferedIOBase):
    """
    Simple writable BufferedIOBase implementation for a socket
    Does not hold data in a buffer, avoiding any need to call flush().
    """

    def __init__(self, sock):
        self._sock = sock

    def writable(self):
        return True

    def write(self, b):
        if isinstance(b, str):
            print("str to byte")
            b = b.encode()

        self._sock.sendall(b)
        with memoryview(b) as view:
            return view.nbytes

    def fileno(self):
        return self._sock.fileno()
