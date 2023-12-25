import base64

__all__ = ["keys"]

info = [("111", ""), ("222", ""), ("333", ""),("Basic Y2xpZW50MToxMjM=","")]

keys = [base64.b64encode('{}:{}'.format(user, pwd).encode()).decode() for user, pwd in info]

