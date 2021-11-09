# libraries
import os
import socketserver
import threading


# tcp handler --> handles incoming request
class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    clients = []

    def handle(self):
        # self.request is the TCP socket connected to the client
        data = self.request.recv(1024)
        data = data.strip()

        # convert data into http request
        string_data = str(data, "UTF-8")

        if string_data != "":
            # split data into an array
            data_list = string_data.split('\r\n')

            # get the request line
            request_line = data_list[0].split(" ")

            # get request
            if request_line[0] == "GET":
                print("Get Request")

            # post request
            elif request_line[0] == "POST":
                print("Post Request")

            # put request
            elif request_line[0] == "PUT":
                print("Put Request")

            # delete request
            elif request_line[0] == "DELETE":
                print("Delete Request")


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 8000

    server = ThreadedTCPServer((HOST, PORT), ThreadedTCPRequestHandler)
    with server:
        ip, port = server.server_address

        # Start a thread with the server -- that thread will then start one
        # more thread for each request
        server_thread = threading.Thread(target=server.serve_forever)

        # Exit the server thread when the main thread terminates
        server_thread.daemon = True
        server_thread.start()
        print("Server loop running in thread:", server_thread.name)

        server.serve_forever()
