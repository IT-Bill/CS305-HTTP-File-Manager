class HTTPRequestHandler:
    def __init__(self, request, client_address, server):
        self.request = request
        self.client_address = client_address
        self.server = server
        
        self.setup()

        try:
            self.handle()
        finally:
            self.finish()
    
    def setup(self):
        """ Setup the request socket """
        pass 

    def handle(self):
        """ Handle the http request """
        self.close_connection = True # !

        self.handle_one_request()
        while not self.close_connection:
            self.handle_one_request()

    def handle_one_request(self):
        """ Handle a single HTTP request """
        

    def finish(self):
        """  """
        pass
        