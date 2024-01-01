import uuid
import time
from .auth import BasicAuth
from lib.config import COOKIE_MAX_AGE

class CookieJar:
    DEFAULT_COOKIE_NAME = "session-id"
    _cookies_cache = {}

    def __init__(self):
        self.cookies = {}

    def __str__(self):
        return '; '.join(["{}={}".format(k, v) for k, v in self.cookies.items()])

    @classmethod
    def generate_cookie(cls, username, max_age=COOKIE_MAX_AGE):
        cookie = CookieJar()
        session_id = str(uuid.uuid4())
        cookie.cookies = {
            CookieJar.DEFAULT_COOKIE_NAME: session_id,
            "max-age": max_age
        }

        CookieJar._cookies_cache[session_id] = {
            "username": username,
            "cookie": cookie, 
            "expires": time.time() + max_age
        }
        return cookie
    
    @classmethod
    def from_cookie_header(cls, header):
        if header is None:
            return None
        
        # The method only takes the first cookie if there are two or more cookies.
        cookie = CookieJar()
        session_id = header.split(";")[0].split("=", maxsplit=1)[1]
        cookie.cookies[CookieJar.DEFAULT_COOKIE_NAME] = session_id
        return cookie

    @property
    def valid(self) -> bool:
        cache = CookieJar._cookies_cache.get(self.cookies.get(CookieJar.DEFAULT_COOKIE_NAME))
        if cache and cache["expires"] > time.time():
            return True
        return False
    
    @property
    def username(self):
        return CookieJar._cookies_cache[self.cookies[CookieJar.DEFAULT_COOKIE_NAME]]['username']
