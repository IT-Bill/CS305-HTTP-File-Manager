from lib.http import HTTPStatus, HTTPMessage
from lib import utils
from lib.http.HTTPMessage import Response, Request
from lib.http.cookiejar import CookieJar
from lib.http.auth import BasicAuth
from lib.utils.logger import logger
import urllib, pathlib, posixpath, mimetypes, threading
import os, io, sys, shutil, time, math
import traceback, select
from lib.config import ST, CONNECTION_TIMEOUT
from cryptography.hazmat.primitives import hashes, serialization


class HTTPRequestHandler:
    NO_NEED_AUTH_PATH = [
        "/favicon.ico",
        "/login.html",
        "/login",
        "/background.jpg",
        "/public_key",
        "/receive_symmetric_key",
        "/encrypted_endpoint"
    ]

    def __init__(self, request, client_address, server):
        self.request = request
        self.client_address = client_address
        self.server = server

        # encryption
        self.private_key, self.public_key = utils.generate_rsa_keys()

        self.directory = os.path.join(os.getcwd(), "data")

        self.use_cookie = False

        self.rfile = self.request.makefile("rb", -1)
        self.setup()

        try:
            self.handle()
        except Exception as e:
            logger.warning(e)
        finally:
            self.finish()

    def setup(self):
        """Setup the request socket"""
        self.wfile = _SocketWriter(self.request)

        self._request = Request()
        self._response = Response(self.wfile)

        self.close_connection = True

    def handle(self):
        """Handle the http request"""

        self.handle_one_request()
        while not self.close_connection:
            self.setup()
            self.handle_one_request()


    def handle_one_request(self):
        """Handle a single HTTP request"""
        # `readline` is used to read one line of request message
        ready_to_read, _, _ = select.select([self.request], [], [], CONNECTION_TIMEOUT)
        if ready_to_read:
            start_line = str(self.rfile.readline(65537), "iso-8859-1").rstrip("\r\n")
        else:
            logger.warning("Connection %s timeout", threading.current_thread().getName())
            self.close_connection = True
            return

        parts = start_line.split()
        if len(parts) < 3:
            logger.warning("Malformed request line: %s", start_line)
            self.close_connection = True
            return
        
        # GET /path HTTP/1.1
        command, path, _ = start_line.split()
        path = urllib.parse.unquote(path)  # Prevent wrong quote in Windows
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
        if conn:
            if conn.lower() == "close":
                self.close_connection = True
            elif conn.lower() == "keep-alive":
                self.close_connection = False
        else:
            self.close_connection = True

    def send_chunked_response(self, f):
        """Send data in chunks for chunked transfer encoding."""
        self._response.add_header("Transfer-Encoding", "chunked")
        self._response.remove_header("Content-Length")
        self._response.write_headers()
        
        while True:
            chunk = f.read(8192)
            if not chunk:
                break

            self.wfile.write(f"{len(chunk):X}\r\n".encode())
            self.wfile.write(chunk)
            self.wfile.write(b"\r\n")

        self.wfile.write(b"0\r\n\r\n")
    
    def send_range_response(self, f):
        def write_chunk(data):
            """Write a chunk of data for chunked transfer encoding."""
            size = f'{len(data):X}\r\n'
            self.wfile.write(size.encode())
            self.wfile.write(data)
            self.wfile.write(b'\r\n')
                    
        range_header = self._request.get_header("Range")
        # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        self._response.remove_header("Content-Length")  # !!!!!!
        # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

        file_size = os.path.getsize(f.name)
        # hot-fix
        if range_header.endswith("-"):
            range_header += str(file_size - 1)
            
        ranges = [
            tuple(map(int, r.split("-")))
            for r in range_header[range_header.index("bytes=") + 6 :].split(
                ","
            )
        ]
        if all(0 <= start <= end < file_size for start, end in ranges):
            boundary = "3d6b6a416f9b5"
            self._response.add_header(
                "Content-Type",
                f"multipart/byteranges; boundary={boundary}",
            )
            self._response.add_header("Transfer-Encoding", "chunked") 

            # Partial Content
            self._response.set_status_line(HTTPStatus.PARTIAL_CONTENT)
            self._response.write_headers()

            for range_start, range_end in ranges:
                f.seek(range_start)
                chunk_header = f"--{boundary}\r\n"
                chunk_header += f"Content-Type: {mimetypes.guess_type(f.name)[0]}\r\n"
                chunk_header += f"Content-Range: bytes {range_start}-{range_end}/{file_size}\r\n\r\n"
                write_chunk(chunk_header.encode())

                chunk_data = f.read(range_end - range_start + 1)
                write_chunk(chunk_data)
                write_chunk(b'\r\n')

            ending_boundary = f"--{boundary}--\r\n"
            write_chunk(ending_boundary.encode())

            # Send a zero-length chunk to indicate the end of the response
            write_chunk(b'')
        else:
            # Range Not Satisfiable
            self.response_error(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
            self._response.write_headers()
    
    def send_encryption_response(self, f):
        # 假设所有内容已经用对称密钥加密
        encrypted_content = utils.symmetric_encrypt_msg(f.read(), self.symmetric_key)
        self._response.add_header("Content-type", "application/octet-stream")
        self._response.set_status_line(HTTPStatus.OK)
        self._response.write_headers()
        self.wfile.write(encrypted_content)

    def do_GET(self):
        """Serve a GET request"""
        f = self.send_head()
        if f:
            try:
                # chunked transfer
                if self._request.query.get("chunked") == ["1"]:
                    self.send_chunked_response(f)
                elif self._request.get_header("Range"):
                    self.send_range_response(f)
                elif self._request.get_header("encryption") == ["1"]:
                    self.send_encryption_response(f)
                else:
                    self._response.write_headers()
                    shutil.copyfileobj(f, self.wfile)
            finally:
                f.close()

    def handle_post_request(self):
        """处理 POST 请求的数据"""
        # 这里应该包含读取请求体的逻辑
        # 如果数据是加密的，这里应该解密数据
        # 返回解密后的数据或原始数据
        length = int(self._request.get_header('content-length'))
        data = self.rfile.read(length)
        return data

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

    def is_method_not_allowed(self):
        if self._request.cmd in ["GET", "HEAD"]:
            return False
        elif self._request.cmd == "POST":
            if self._request.simple_path not in ["/upload", "/delete"]:
                self.response_error(HTTPStatus.METHOD_NOT_ALLOWED)
                self._response.write_headers()
                return True

            else:
                return False

    def handle_encrypted_endpoint(self):
        # 从请求中读取加密数据
        encrypted_data = self.handle_post_request()

        # 使用对称密钥解密数据
        try:
            if self.symmetric_key:
                decrypted_data = utils.symmetric_decrypt_msg(encrypted_data, self.symmetric_key)
                # 根据业务需求处理解密后的数据
                # 例如，这里可以根据解密后的数据执行特定操作
                print(decrypted_data)

                # 准备响应数据
                response_data = b"Response to encrypted request"
                encrypted_response_data = utils.symmetric_encrypt_msg(response_data, self.symmetric_key)

                # 发送加密的响应
                self._response.set_status_line(HTTPStatus.OK)
                self._response.add_header("Content-type", "application/octet-stream")
                self._response.add_header("Content-Length", str(len(encrypted_response_data)))
                self._response.write_headers()
                self.wfile.write(encrypted_response_data)
            else:
                self.response_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Symmetric key not set")

        except Exception as e:
            print("Failed to decrypt/encrypt message:", e)
            self.response_error(HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self):
        """Serve a POST request"""
        # 处理加密密钥接收
        if self._request.path == "/receive_symmetric_key":
            encrypted_key = self.handle_post_request()
            self.receive_and_decrypt_symmetric_key(encrypted_key)
            return
        
        elif self._request.path == "/encrypted_endpoint":
            self.handle_encrypted_endpoint()
            return

        elif self._request.path in ["/login", "/login.html"]:
            # 从payload中获取用户名和密码
            payload = self.handle_post_request().decode()
            # 按照&分割
            payload = payload.split("&")
            username = payload[0].split("=")[1]
            password = payload[1].split("=")[1]
            # print(password)
            # 验证用户名和密码
            if self.is_unauthorized(username, password):
                # 给浏览器弹窗
                self.serve_html_file("lib/templates/login.html")
            else:
                # 重定向到主页
                self.redirect(
                    utils.join_path_query(
                        os.path.join("/", self._request.auth.username, ""),
                        {ST: "0"},
                    )
                )
            return

        if (
            self.is_unauthorized()
            or self.is_method_not_allowed()
            or self.is_bad_request()
            or self.is_forbidden()
        ):
            return

        if self._request.simple_path == "/upload":
            self.upload()
        elif self._request.simple_path == "/delete":
            self.delete()

    def do_HEAD(self):
        """Serve a HEAD request"""
        f = self.send_head()
        self._response.write_headers()
        if f:
            f.close()

    def send_public_key(self):
        # 假设 self.public_key 已经在服务器启动时生成
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self._response.set_status_line(HTTPStatus.OK)
        self._response.add_header("Content-Type", "application/x-pem-file")
        self._response.add_header("Content-Length", str(len(public_key_pem)))
        self._response.write_headers()
        self.wfile.write(public_key_pem)

    def receive_and_decrypt_symmetric_key(self, encrypted_key):
        # 解密由客户端发送的加密的对称密钥
        try:
            decrypted_key = utils.decrypt_msg_with_private_key(encrypted_key, self.private_key)
            self.symmetric_key = decrypted_key
            self._response.set_status_line(HTTPStatus.OK)
            self._response.add_header("Content-Length", 0)
            self._response.write_headers()
        except Exception as e:
            print("Failed to decrypt symmetric key:", e)
            self.response_error(HTTPStatus.BAD_REQUEST)

    def send_head(self):
        # if self._request.path not in HTTPRequestHandler.NO_NEED_AUTH_PATH and (
        #     self.is_unauthorized() or self.is_forbidden() or self.is_bad_request()
        # ):
        if self._request.path not in HTTPRequestHandler.NO_NEED_AUTH_PATH and (
            self.is_unauthorized() or self.is_bad_request()
        ):
            return None
        elif self._request.path in ["/login.html", "/login"]:
            self.serve_html_file("lib/templates/login.html")
            return None
        elif self._request.path == "/background.jpg":
            self.serve_html_file("lib/templates/background.jpg")
            return None
        elif self._request.path == "/public_key":
            self.send_public_key()
            return None

        path = self.path2local(self._request.path)
        f = None
        if os.path.isdir(path):
            # parts = urllib.parse.urlsplit(self._request.path)
            # if not parts.path.endswith("/"):
            #     # Example: Redirect `/dir` to `/dir/`
            #     new_parts = (parts[0], parts[1], parts[2] + "/", parts[3], parts[4])
            #     new_url = urllib.parse.urlunsplit(new_parts)
            #     self.redirect(new_url, HTTPStatus.PERMANENT_REDIRECT)
            #     return None
            # for index in "index.html", "index.htm":
            #     index = os.path.join(path, index)
            #     if os.path.exists(index):
            #         path = index
            #         break
            # else:
            return self.list_directory(path)

        # check whether client needs public key
        if self._request.path == "/get_public_key":
            self._response.set_status_line(HTTPStatus.OK)
            self._response.add_header("Server-Key", self.public_key)
            self._request.write_headers()
            return None

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
            self._response.add_header("Content-Length", 0)
            self._response.write_headers()

        except OSError:
            self.response_error(HTTPStatus.INTERNAL_SERVER_ERROR)

    def upload(self):
        path = self.path2local(self._request.query["path"][0])

        if not os.path.isdir(path):
            # the directory does not exist
            self.response_error(HTTPStatus.NOT_FOUND)
            return

        # process multipart
        content_type = self._request.get_header('Content-Type')
        boundary = utils.get_boundary(content_type)
        if not boundary:
            self.response_error(HTTPStatus.BAD_REQUEST)
            return

        content_length = int(self._request.get_header('Content-Length'))
        file_data = self.rfile.read(content_length)

        for headers, body in utils.parse_multipart(file_data, boundary):
            disposition, disp_params = utils.parse_content_disposition(headers.get('content-disposition', ''))
            if disposition == 'form-data' and 'filename' in disp_params:
                file_name = disp_params['filename']
                file_path = os.path.join(path, file_name)
                with open(file_path, 'wb') as file:
                    file.write(body)

        self._response.set_status_line(HTTPStatus.OK)
        self._response.add_header("Content-Length", 0)
        self._response.write_headers()

    def is_bad_request(self):
        if self._request.cmd in ["GET", "HEAD"]:
            # check SUSTech-HTTP query
            # not dir
            if (
                os.path.isfile(self.path2local(self._request.path))
                or self._request.query.get(ST)
                and self._request.query[ST] in (["0"], ["1"])
            ):
                return False  # correct

        elif self._request.cmd == "POST":
            if (
                self._request.query.get("path") != None
                and len(self._request.query["path"]) == 1
            ):
                return False  # correct

        self.response_error(HTTPStatus.BAD_REQUEST)
        return True


    def is_unauthorized(self, username=None, password=None):
        """
        Varify the authorization.
        """

        def set_unauthorized_response():
            self._response.set_status_line(HTTPStatus.UNAUTHORIZED)
            self._response.add_header("WWW-Authenticate", 'Basic realm="Test"')
            self._response.add_header("Content-Length", 0)
            self._response.write_headers()
            self.close_connection = False

        if username != None and password != None:
            auth = BasicAuth(username, password)
            if auth and auth.valid:
                self._request.auth = auth
                self._response.add_header(
                    "Set-Cookie", str(CookieJar.generate_cookie(auth.username))
                )
                return False
            else:
                return True

        cookie = CookieJar.from_cookie_header(self._request.get_header("Cookie"))
        if cookie and cookie.valid:
            self._request.cookie = cookie
            self._request.auth = BasicAuth(cookie.username, None)  # set to None
            return False

        auth = BasicAuth.from_auth_header(self._request.get_header("authorization"))
        if auth and auth.valid:
            self._request.auth = auth
            self._response.add_header(
                "Set-Cookie", str(CookieJar.generate_cookie(auth.username))
            )

            return False

        # send UNAUTHORIZED header
        set_unauthorized_response()
        return True

    def is_forbidden(self):
        """
        Check whether the path is forbidden.
        """

        if self._request.cmd in ["GET", "HEAD"]:
            segments = [
                seg
                for seg in posixpath.normpath(
                    urllib.parse.unquote(
                        self._request.path.split("?", 1)[0].split("#", 1)[0]
                    )
                ).split("/")
                if seg
            ]

            # visit the root directory of data is allowed.
            if (
                len(segments) == 0
                or os.path.isfile(self.path2local(self._request.path))
                or segments[0] == self._request.auth.username
            ):
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
        # 让浏览器从response里面，得到下次发get请求、访问的url
        self._response.set_status_line(status)
        self._response.add_header("Location", new_url)
        self._response.add_header("Content-Length", "0")
        self._response.write_headers()

    def convert_size(self,size_bytes):
        if size_bytes == 0:
            return "0B"
        size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p)
        return "%s %s" % (s, size_name[i])

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
        mode = self._request.query[ST][0]
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

            content = str(display_list)

        elif mode == "0":
            r = []
            displaypath = utils.html_escape(self._request.simple_path, quote=False)
            title = "Directory listing for %s" % displaypath
            r.append("<!DOCTYPE html>")
            r.append("<html>\n<head>")
            r.append(
                '<meta http-equiv="Content-Type" '
                'content="text/html; charset=%s">' % enc
            )
            r.append("<title>%s</title>\n</head>" % title)
            # 添加样式
            r.append("<style>")
            r.append(
                """
                html, body {
                    height: 100%;
                    margin: 0;
                    padding: 0;
                    font-family: Arial, sans-serif;
                }
                body {
                    background-image: url('background.jpg'); /* 替换为您的背景图片 URL */
                    background-size: cover; /* 背景图片覆盖整个元素区域 */
                    background-position: center; /* 背景图片居中 */
                    background-attachment: fixed; /* 背景图片固定，不随内容滚动 */
                    background-repeat: no-repeat; /* 背景图片不重复 */
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    color: white; /* 根据您的背景颜色调整文字颜色 */
                }
                .container {
                    width: 80%;
                    background: rgba(0, 0, 0, 0.8);
                    padding: 20px;
                    border-radius: 10px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
                    z-index: 2;
                }
                .header {
                    text-align: center;
                    padding: 20px;
                    font-size: 3em;
                    color: red;
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    font-weight: bold;
                    text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.5);
                }
                h1 {
                    text-align: center;
                    font-size: 2em;
                    color: #4CAF50;
                }
                ul {
                    list-style-type: none;
                    padding: 0;
                }
                li {
                    padding: 8px 15px;
                    border-bottom: 1px solid #ddd;
                }
                li a {
                    text-decoration: none;
                    color: #ffffff;
                    display: block;
                }
                li a:hover {
                    background-color: #f8f8f8;
                    color: black;
                }
                hr {
                    border: none;
                    background-color: #ddd;
                    height: 1px;
                }
            """
            )
            r.append("</style>")
            r.append("<script>")
            r.append(
                """
                function handleDelete(filename) {
    fetch('http://127.0.0.1:8080/delete?path=@#￥%…………&' + filename, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      }
    })
            .then(response => {
              // Handle the response as needed
              // For example, you can check if the response indicates successful deletion

              // Reload the page after deletion
              window.location.reload();
            })
            .catch(error => {
              // Handle errors if needed
              console.error('Error deleting file:', error);
            });
                    }
                    
  function uploadFile() {
            var fileInput = document.getElementById('fileInput');
            var file = fileInput.files[0];
            var formData = new FormData();
            formData.append('file', file);

            fetch('http://127.0.0.1:8080/upload?path=@#￥%…………&', {
                method: 'POST',
                body: formData
            })
            .then(response => response.text())
            .then(data => {
                console.log(data);
                alert('文件上传成功');
                window.location.reload(); // 刷新页面
            })
            .catch(error => {
                console.error('文件上传失败:', error);
                alert('文件上传失败');
            });
        }
                
            """.replace(
                    "@#￥%…………&", displaypath
                )
            )
            r.append("</script>")
            r.append("</head>")

            # 主体内容
            r.append("<body>")
            r.append("<div class='header'>HTTP FILE MANAGER</div>")
            r.append("<div class='container'>")
            r.append(
                '<input type="file" id="fileInput" '
                + "/><button onclick='uploadFile()'>Upload File</button>"
            )
            r.append("<h1>%s</h1>" % title)
            r.append("<ul>")

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
                # print(name)
                fullname = os.path.join(path, name)
                file_size_bytes = os.path.getsize(fullname)
                file_size_formatted = self.convert_size(file_size_bytes)
                modification_time = time.ctime(os.path.getmtime(fullname))
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
                    '<li><a href="%s">%s</a> - Size: %s, Last Modified: %s</li>'
                    % (linkname, utils.html_escape(displayname, quote=False), file_size_formatted, modification_time)
                )
                # print(displayname)
                # 在每个列表项中添加删除按钮
                r.append(
                    "<button onclick=\"handleDelete('%s')\">Delete</button>"
                    % displayname
                )
            # 结束页面内容
            r.append("</ul>\n<hr>\n</body>\n</html>\n")
            content = "\n".join(r)

        # ! Pay attention to indent.
        # 创建和返回响应
        # encoded = (content + '\r\n').encode(enc)
        encoded = (content).encode(enc)

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
        # self.close_connection = True

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
            b = b.encode()

        self._sock.sendall(b)
        with memoryview(b) as view:
            return view.nbytes

    def fileno(self):
        return self._sock.fileno()
