import time, datetime, urllib, re
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet

__all__ = [
    "formatdate",
    "parse_url",
    "get_filename_from_content_disposition",
    "join_path_query",
    "html_escape",
]


def formatdate(timeval=None, localtime=False, usegmt=False):
    """Returns a date string as specified by RFC 2822, e.g.:

    Fri, 09 Nov 2001 01:08:47 -0000

    Optional timeval if given is a floating point time value as accepted by
    gmtime() and localtime(), otherwise the current time is used.

    Optional localtime is a flag that when True, interprets timeval, and
    returns a date relative to the local timezone instead of UTC, properly
    taking daylight savings time into account.

    Optional argument usegmt means that the timezone is written out as
    an ascii string, not numeric one (so "GMT" instead of "+0000"). This
    is needed for HTTP, and is only used when localtime==False.
    """
    if timeval is None:
        timeval = time.time()

    # Format the date according to RFC 2822
    if localtime:
        # Local time with timezone
        tuple_time = time.localtime(timeval)
        date_str = time.strftime("%a, %d %b %Y %H:%M:%S", tuple_time)
        if usegmt:
            # Append 'GMT' if usegmt is True
            date_str += " GMT"
        else:
            # Compute the local timezone offset
            offset = datetime.datetime.now() - datetime.datetime.utcnow()
            total_seconds = int(offset.total_seconds())
            sign = "+" if total_seconds > 0 else "-"
            hours_offset = abs(total_seconds) // 3600
            minutes_offset = (abs(total_seconds) % 3600) // 60
            date_str += " {}{:02d}{:02d}".format(sign, hours_offset, minutes_offset)
    else:
        # UTC/GMT time
        tuple_time = time.gmtime(timeval)
        date_str = time.strftime("%a, %d %b %Y %H:%M:%S", tuple_time)
        if usegmt:
            date_str += " GMT"
        else:
            date_str += " +0000"

    return date_str


def parse_url(url):
    """
    parse url to plain path and query dictionary
    """
    parts = urllib.parse.urlsplit(url)
    path = parts.path
    query = urllib.parse.parse_qs(parts.query)
    if query.get("SUSTech-HTTP") == None:
        query["SUSTech-HTTP"] = ["0"]
    return path, query


def get_filename_from_content_disposition(content_disposition):
    """
    Extracts filename from the Content-Disposition header.
    """
    if not content_disposition:
        return None
    filename_regex = r"filename\*?=(?:UTF-8\'\')?(.+)"  # Regex to extract filename
    matches = re.finditer(filename_regex, content_disposition, re.IGNORECASE)
    for match in matches:
        if match.group(1):
            # The filename might be URL-encoded
            filename = urllib.parse.unquote_plus(match.group(1).strip('"'))
            return filename
    return None


def join_path_query(path, query_params):
    # 初始化查询参数字符串
    query_string = ""
    # 遍历字典中的每个键值对
    for key, values in query_params.items():
        # 确保值是一个列表
        if not isinstance(values, list):
            values = [values]
        # 对于每个值，添加到查询字符串
        for value in values:
            if query_string:
                query_string += "&"
            query_string += urllib.parse.urlencode({key: value})

    # 构造完整的URL
    return urllib.parse.urlunsplit(("", "", path, query_string, ""))


def html_escape(s, quote=True):
    """
    Replace special characters "&", "<" and ">" to HTML-safe sequences.
    If the optional flag quote is true (the default), the quotation mark
    characters, both double quote (") and single quote (') characters are also
    translated.
    """
    s = s.replace("&", "&amp;")  # Must be done first!
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    if quote:
        s = s.replace('"', "&quot;")
        s = s.replace("'", "&#x27;")
    return s


# ----------------------- Server -------------------------
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_message(symmetric_key, message):
    if symmetric_key:
        return Fernet(symmetric_key).encrypt(message)
    else:
        raise Exception("Symmetric key not set")



def generate_symmetric_key():
    return Fernet.generate_key()


def encrypt_msg_with_public_key(msg, public_key):
    encrypted_msg = public_key.encrypt(
        msg,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        ),
    )
    return encrypted_msg


def decrypt_msg_with_private_key(encrypted_msg, private_key):
    decrypted_msg = private_key.decrypt(
        encrypted_msg,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        ),
    )
    return decrypted_msg


def symmetric_encrypt_msg(msg, key):
    f = Fernet(key)
    return f.encrypt(msg)


def symmetric_decrypt_msg(encrypted_msg, key):
    f = Fernet(key)
    return f.decrypt(encrypted_msg)


def decrypt_symmetric_key(private_key, encrypted_key):
    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return decrypted_key


def decrypt_msg(symmetric_key, encrypted_msg):
    if symmetric_key:
        return Fernet(symmetric_key).decrypt(encrypted_msg)
    else:
        return None


# --------------------------- Client ----------------------
def encrypt_msg_with_public_key(msg, public_key_pem):
    public_key = load_pem_public_key(public_key_pem, backend=default_backend())
    encrypted_msg = public_key.encrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return encrypted_msg


def symmetric_encrypt_msg(msg, key):
    f = Fernet(key)
    return f.encrypt(msg)
