__all__ = ["COOKIE_MAX_AGE", "ST"]

COOKIE_MAX_AGE = 120
ST = "SUSTech-HTTP"

USER_INFO = {
    "111": "",
    "222": "",
    "333": "",
    "client1": "123",
    "client2": "123",
    "client3": "123",
}

# If the server not receives any request during `CONNECTION_TIMEOUT` seconds from some threads
# the server will close these threads.
CONNECTION_TIMEOUT = 20
