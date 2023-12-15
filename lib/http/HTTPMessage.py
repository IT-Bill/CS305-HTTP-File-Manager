class HTTPMessage:

    def __init__(self):
        self.headers = {}


    @staticmethod
    def parse_headers(fp):
        msg = HTTPMessage()
        
        while True:
            line = fp.readline(1024)
            if line in (b'\r\n', b'\n', b''):
                break
            
            # split by `: `
            k, v = tuple(str(line, 'iso-8859-1').strip('\r\n').split(": ", maxsplit=1))
            msg.headers[k.lower()] = v
        
        return msg
    
    def __getitem__(self, k):
        return self.headers.get(k.lower(), "")