from base64 import b64encode, b64decode
from lib.config import USER_INFO

def _basic_auth_str(username, password):
    """Return a Basic Auth string."""
    if isinstance(username, str):
        username = username.encode("latin1")
    if isinstance(username, str):
        password = password.encode("latin1")

    authstr = (
        "Basic " + b64encode(b":".join((username, password))).decode("ascii").strip()
    )
    return authstr

class BasicAuth:
    def __init__(self, username, password):
        self.username = username
        self.password = password
    
    def __eq__(self, other) -> bool:
        return all(
            [
                self.username == getattr(other, "username", None),
                self.password == getattr(other, "password", None),
            ]
        )
    
    @classmethod
    def from_auth_header(cls, header):
        if header is None:
            return None
        
        key = header.split(maxsplit=1)[1]
        username, password = b64decode(key).decode("ascii").split(":", maxsplit=1)
        auth = BasicAuth(username, password)
        return auth
    
    @property
    def valid(self):
        return USER_INFO.get(self.username) == self.password



