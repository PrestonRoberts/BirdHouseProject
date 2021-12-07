# libraries
import os
import socketserver
import threading
import json


# new response
def new_response(**kwargs):
    request = kwargs["request"]
    response = "HTTP/1.1 "

    # 101
    if kwargs["code"] == "101":
        response += "101 Switching Protocols\r\n"\
                    "Upgrade: websocket\r\n"\
                    "Connection: Upgrade\r\n"\
                    "Sec-WebSocket-Accept: " + kwargs["hash_key"] + "\r\n\r\n"
        response = response.encode("utf-8")
    # 200
    elif kwargs["code"] == "200":
        content = kwargs["content"]
        if kwargs["contentType"] != "image/jpeg":
            content = content.encode("utf-8")
        response += "200 OK" + "\r\n"
        if "visits" in kwargs:
            response += "Set-Cookie: visits=" + kwargs["visits"] + "; Max-Age=3600" + "\r\n"
        if "user_token" in kwargs:
            response += "Set-Cookie: user_token=" + kwargs["user_token"] + "; HttpOnly" + "\r\n"
        response += "Content-Type: " + kwargs["contentType"]
        if "charset" in kwargs:
            response += "; charset=" + kwargs["charset"] + "\r\n"
        else:
            response += "\r\n"
        response += "Content-Length: " + str(len(content)) + "\r\n"\
            "X-Content-Type-Options: nosniff" + "\r\n\r\n"
        response = response.encode("utf-8") + content
    # 201
    elif kwargs["code"] == "201":
        content = json.dumps(kwargs["content"], default=str).encode("utf-8")
        response += "201 Created" + "\r\n\r\n"
        response = response.encode("utf-8") + content
    # 301
    elif kwargs["code"] == "301":
        response += "301 Moved Permanently" + "\r\n" \
            "Content-Length: 0" + "\r\n" \
            "Location: " + kwargs["location"]
        response = response.encode("utf-8")
    # 403
    elif kwargs["code"] == "403":
        response += "403 Request Rejected" + "\r\n" \
            "Content-Type: " + kwargs["contentType"]
        if "charset" in kwargs:
            response += "; charset=" + kwargs["charset"] + "\r\n"
        else:
            response += "\r\n"
        response += "Content-Length: " + str(len(kwargs["content"])) + \
            "\r\n" \
            "X-Content-Type-Options: nosniff" + "\r\n\r\n" + \
            kwargs["content"]
        response = response.encode("utf-8")
    # 404
    else:
        response += "404 Not Found" + "\r\n" \
            "Content-Type: " + kwargs["contentType"]
        if "charset" in kwargs:
            response += "; charset=" + kwargs["charset"] + "\r\n"
        else:
            response += "\r\n"
        response += "Content-Length: " + str(len(kwargs["content"])) + \
                    "\r\n" \
                    "X-Content-Type-Options: nosniff" + "\r\n\r\n" + \
                    kwargs["content"]
        response = response.encode("utf-8")

    request.sendall(response)


# tcp handler --> handles incoming request
class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    clients = []

    def handle(self):
        # self.request is the TCP socket connected to the client
        data = self.request.recv(1024)
        data = data.strip()

        # convert data into http request
        string_data = str(data, "UTF-8")

        # split data
        data_split = string_data.split("\r\n")

        if string_data != "":
            # split data into an array
            data_list = string_data.split('\r\n')

            # get the request line
            request_line = data_list[0].split(" ")

            # turn request into a dictionary
            data_dict = {"Request": request_line[0], "URL": request_line[1]}
            for d in data_split:
                v = d.split(": ")
                if len(v) > 1:
                    data_dict[v[0]] = v[1]

            print(data_dict)

            # get request
            if data_dict["Request"] == "GET":
                # landing page
                if data_dict["URL"] == "/":
                    content = open("./static/index.html").read()
                    new_response(code="200", content=content, contentType="text/html", charset="utf-8",
                                 request=self.request)

                # login page
                elif data_dict["URL"] == "/login":
                    content = open("./static/login.html").read()
                    new_response(code="200", content=content, contentType="text/html", charset="utf-8",
                                 request=self.request)

                # register page
                elif data_dict["URL"] == "/register":
                    content = open("./static/register.html").read()
                    new_response(code="200", content=content, contentType="text/html", charset="utf-8",
                                 request=self.request)

                # home page
                elif data_dict["URL"] == "/home":
                    content = open("./static/home.html").read()
                    new_response(code="200", content=content, contentType="text/html", charset="utf-8",
                                 request=self.request)

                else:
                    # Load other file types
                    pages = []

                    # The path for listing items
                    css_path = './static/css'
                    js_path = './static/js'

                    # The list of items
                    css_files = os.listdir(css_path)
                    js_files = os.listdir(js_path)

                    # Loop to get all files
                    for filename in css_files:
                        if '.' in filename:
                            pages.append("/css/" + filename)

                    for filename in js_files:
                        if '.' in filename:
                            pages.append("/js/" + filename)

                    # check if page exists
                    if data_dict["URL"] in pages:
                        # load file
                        filename = request_line[1][1:]
                        content = open("./static/" + filename).read()

                        # css file
                        if ".css" in filename:
                            content_type = "text/css"
                            new_response(code="200", content=content, contentType=content_type, charset="utf-8",
                                         request=self.request)

                        # javascript file
                        elif ".js" in filename:
                            content_type = "text/javascript"
                            new_response(code="200", content=content, contentType=content_type, charset="utf-8",
                                         request=self.request)

                        # 404 Error
                        else:
                            content = open("./static/404.html").read()
                            new_response(code="404", content=content, contentType="text/html", charset="utf-8",
                                         request=self.request)

            # post request
            elif data_dict["Request"] == "POST":
                # TODO user login
                if data_dict["URL"] == "/user_login":
                    print("User Login")
                # TODO user register
                elif data_dict["URL"] == "/user_register":
                    print("User Login")


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
