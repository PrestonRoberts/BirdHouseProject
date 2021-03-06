# libraries
import base64
import os
import socketserver
import sys
import threading
import json
import bcrypt
import random
import string
import hashlib

# connect to database
from bson import json_util

import database
from database import user_collection
from socket_server import SocketClass


# new response
def new_response(**kwargs):
    request = kwargs["request"]
    response = "HTTP/1.1 "

    # 101
    if kwargs["code"] == "101":
        response += "101 Switching Protocols\r\n" \
                    "Upgrade: websocket\r\n" \
                    "Connection: Upgrade\r\n" \
                    "Sec-WebSocket-Accept: " + kwargs["hash_key"] + "\r\n\r\n"
        response = response.encode("utf-8")

    # 200
    elif kwargs["code"] == "200":
        content = kwargs["content"]
        if kwargs["contentType"] != "image/jpeg" and kwargs["contentType"] != "application/json":
            content = content.encode("utf-8")
        if kwargs["contentType"] == "application/json":
            content = json_util.dumps(content).encode('utf8')
        response += "200 OK" + "\r\n"
        if "visits" in kwargs:
            response += "Set-Cookie: visits=" + kwargs["visits"] + "; Max-Age=3600" + "\r\n"
        if "token" in kwargs:
            response += "Set-Cookie: user_token=" + kwargs["token"] + "; HttpOnly" + "\r\n"
        response += "Content-Type: " + kwargs["contentType"]
        if "charset" in kwargs:
            response += "; charset=" + kwargs["charset"] + "\r\n"
        else:
            response += "\r\n"
        response += "Content-Length: " + str(len(content)) + "\r\n" \
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

        print(response)
    request.sendall(response)


# clean string
def clean_string(input_str):
    clean_str = normal_string(input_str)

    # prevent html attack
    clean_str = clean_str.replace("&", "&amp")
    clean_str = clean_str.replace("<", "&lt")
    clean_str = clean_str.replace(">", "&gt")

    return clean_str


# convert to normal string
def normal_string(input_str):
    # convert to normal string
    normal_str = input_str.replace("+", " ")
    to_replace = []
    for x in range(len(normal_str)):
        if normal_str[x] == "%":
            char = normal_str[x + 1:x + 3]
            if char not in to_replace:
                to_replace.append(char)

    normal_str = normal_str.replace("%", "")

    for char in to_replace:
        normal_str = normal_str.replace(char, chr(int(char, 16)))

    return normal_str


# check if username is valid
def check_username(username):
    # minimum length of 3, maximum length of 16
    length = len(username)
    if length < 3 or length > 16:
        return False, "Username must be between 3 and 16 characters long"

    # only english characters and numbers
    allowed_characters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
                          't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
                          'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2', '3', '4', '5',
                          '6', '7', '8', '9', '0']

    if any(x not in allowed_characters for x in username):
        return False, "Username can only contain english letters or numbers"

    return True, "Success"


# check if password is valid
def check_password(password):
    # minimum length 8
    if len(password) <= 8:
        return False, "Password must be at least 8 characters long"

    # 1 lower case character
    has_lower = False
    for char in password:
        if char.islower():
            has_lower = True
            break
    if not has_lower:
        return False, "Password must have at least 1 lower case character"

    # 1 uppercase character
    has_upper = False
    for char in password:
        if char.isupper():
            has_upper = True
            break
    if not has_upper:
        return False, "Password must have at least 1 upper case character"

    # 1 number
    has_digit = False
    for char in password:
        if char.isdigit():
            has_digit = True
            break
    if not has_digit:
        return False, "Password must have at least 1 number"

    # 1 special character
    special_characters = "!@#$%^&*()-+?_=,<>/"
    has_special = False
    for char in password:
        if char in special_characters:
            has_special = True
    if not has_special:
        return False, "Password must have at least 1 special character (!@#$%^&*()-+?_=,<>/)"

    return True, "Success"


# find the cookie you need
def find_cookie(cookies, find):
    cookie = cookies.split(";")
    for c in cookie:
        cookieParts = c.split("=", 1)
        if len(cookieParts) >= 2 and cookieParts[0] == find:
            return cookieParts[1]

    return ""


# find the user that has the matching hash
def match_user(hashes, hashed):
    for h in hashes:
        user = h["username"]
        hashed_user = hash_cookie(user)
        sys.stdout.flush()
        if hashed == hashed_user:
            return user
    return ""


def hash_cookie(obj):
    tokenbytes = base64.b64encode(hashlib.sha256((obj + "bcad35b6961a45159348ae8386c934cd").encode()).digest())
    hashedtoken = tokenbytes.decode('ascii')
    return hashedtoken


def find_user_cookie(cookies):
    hashToken = find_cookie(cookies, "user_token")
    if hashToken != "":
        users = list(user_collection.find({}))
        if len(users) > 0:
            user = match_user(users, hashToken)
            return user
    return ""


def bytes_reading(variable):
    image_file = open("%s.jpg" % variable, "rb")
    image_read_file = image_file.read()
    byte_size = len(image_read_file)
    image_file.close()
    return byte_size


def render(image):
    image += ".jpg"
    rendered_image = " <img src=image/" + image + ">"

    return rendered_image


def byte_content(variable):
    image_file = open("%s.jpg" % variable, "rb")
    image_read_file = image_file.read()
    image_file.close()

    return image_read_file


def html_files(html_format, image_strings, name):
    temp_tags = ""

    with open(html_format) as html_file:
        read_this = html_file.read()

        replace_name = read_this.replace("<title>{{name}}</title>", "<title>welcome human" + name + "</title>")
        for i in image_strings:
            temp_tags += render(i)

        replace_images = replace_name.replace("{{image_holder}}", temp_tags)

    return replace_images


# tcp handler --> handles incoming request
class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    clients = []

    def handle(self):
        # self.request is the TCP socket connected to the client
        data = self.request.recv(2048)
        data = data.strip()

        # convert data into http request
        string_data = str(data, "utf-8", errors='ignore')
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

            # print(data_dict)

            # get request
            if data_dict["Request"] == "GET":
                # landing page
                if data_dict["URL"] == "/":
                    content = open("./static/home.html").read()
                    # return new_response(code="200", content=content, contentType="text/html", charset="utf-8",
                    #                     request=self.request)
                    if "Cookie" in data_dict:
                        user = find_user_cookie(data_dict["Cookie"])
                        if user != "":
                            content = content.replace("Welcome Dummyyyyyyyy", "Welcome " + user, 1)
                            new_response(code="200", content=content, contentType="text/html", charset="utf-8",
                                         request=self.request)
                    else:
                        new_response(code="301", location="/login", request=self.request)

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

                # user page
                elif data_dict["URL"] == "/user":
                    content = open("./static/home.html").read()
                    # return new_response(code="200", content=content, contentType="text/html", charset="utf-8",
                    #                     request=self.request)
                    if "Cookie" in data_dict:
                        user = find_user_cookie(data_dict["Cookie"])
                        if user != "":
                            content = content.replace("Welcome Dummyyyyyyyy", "Welcome " + user, 1)
                            new_response(code="200", content=content, contentType="text/html", charset="utf-8",
                                         request=self.request)
                    else:
                        new_response(code="301", location="/login", request=self.request)
                elif data_dict["URL"] == "/websocket":

                    socket_key = data_dict["Sec-WebSocket-Key"]
                    tokenbytes = base64.b64encode(
                        hashlib.sha1((socket_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode('utf-8')).digest())
                    hashedtoken = tokenbytes.decode('ascii')
                    new_response(code="101", hash_key=hashedtoken, request=self.request)
                    user = find_user_cookie(data_dict["Cookie"])
                    # user = "Oyal2"
                    status = user_collection.find_one({"username": user}).get('status')
                    socket = SocketClass(find_cookie(data_dict["Cookie"], "user_token"), user, self, status)
                    socket.add_client()
                else:
                    # Load other file types
                    pages = []

                    # The path for listing items
                    css_path = './static/css'
                    js_path = './static/js'
                    jpg_path = './static/image'

                    # The list of items
                    css_files = os.listdir(css_path)
                    js_files = os.listdir(js_path)
                    jpg_files = os.listdir(jpg_path)

                    # loops through images
                    for filename in jpg_files:
                        if '.' in filename:
                            pages.append("/image/" + filename)

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
                        content = open("./static/" + filename, encoding="utf8").read()

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
                        elif ".jpg" in filename:  # not sure if we're using jpgs
                            content_type = "image/jpg"
                            new_response(code="200", content=content, content_type=content_type, charset="utf-8",
                                         request=self.request)
                        # 404 Error
                        else:
                            content = open("./static/404.html").read()
                            new_response(code="404", content=content, contentType="text/html", charset="utf-8",
                                         request=self.request)

            # post request
            elif data_dict["Request"] == "POST":
                form_dict = {}

                if "multipart/form-data" in data_dict["Content-Type"]:
                    boundary = data_dict["Content-Type"][data_dict["Content-Type"].index("boundary=") + 9:]
                    if boundary not in data_list:
                        return

                    form_data = data_list[data_list.index(boundary) + 3:len(data_list) - 1]
                    form_dict[boundary] = "".join(form_data)
                    # for f in form_data:
                    #     #v = f.split("\r\n\r\n")
                    #     key = v[0]
                    #     value = clean_string(v[1])
                    #     form_dict[key] = value
                else:
                    # get form data
                    form_data = string_data.split("\r\n\r\n")[1]
                    form_data = form_data.split("&")
                    if data_dict["Content-Type"] == "application/json":
                        form_dict = json.loads(form_data[0])
                    else:
                        for f in form_data:
                            v = f.split("=")
                            key = v[0]
                            value = clean_string(v[1])
                            form_dict[key] = value

                # TODO user login
                if data_dict["URL"] == "/user":
                    # get login information
                    username = form_dict["username"]
                    password = form_dict["password"]

                    # check if user can log in
                    is_valid = True

                    # search database for user
                    query = {"username": username}
                    user = user_collection.find_one(query)
                    if user is None:
                        is_valid = False

                    # check if password matches
                    if is_valid:
                        if bcrypt.checkpw(password.encode(), user["password"]):
                            user_token = hash_cookie(user["username"])

                            # redirect user to home page
                            content = open("./static/home.html").read()
                            content = content.replace("Welcome Dummyyyyyyyy", "Welcome " + user["username"], 1)
                            new_response(code="200", content=content, contentType="text/html", charset="utf-8",
                                         request=self.request, token=user_token)
                        else:
                            is_valid = False

                    # do not log in the user
                    if not is_valid:
                        # TODO display error message on webpage

                        # load login page
                        new_response(code="301", location="/login", request=self.request)

                # TODO user register
                elif data_dict["URL"] == "/user_register":
                    # get register information
                    username = form_dict["username"]
                    password = form_dict["password"]
                    confirm_password = form_dict["confirm_password"]

                    # check if inputs are all valid
                    is_valid = True

                    # check if username is allowed
                    username_allowed, message = check_username(username)
                    if not username_allowed:
                        is_valid = False

                    # check if username is taken
                    if is_valid:
                        query = {"username": username}
                        user = user_collection.find_one(query)
                        if user is not None:
                            message = "Username already taken"
                            is_valid = False

                    # check if passwords match
                    if is_valid:
                        if password != confirm_password:
                            message = "Passwords Do Not Match"
                            is_valid = False

                    # check if password is strong enough
                    if is_valid:
                        password_allowed, message = check_password(password)
                        if not password_allowed:
                            is_valid = False

                    # create account
                    if is_valid:
                        # encrypt password
                        salt = bcrypt.gensalt()
                        encrypted_pass = bcrypt.hashpw(password.encode(), salt)

                        # store username and password in database
                        new_entry = {"username": username, "password": encrypted_pass, "status": "online"}
                        user_collection.insert_one(new_entry)

                        # TODO display success message on webpage
                        print("Account Created Successfully")

                        # load login page
                        new_response(code="301", location="/login", request=self.request)

                    # do not create account
                    if not is_valid:
                        # TODO display error message on webpage
                        print(message)

                        # load register page
                        new_response(code="301", location="/register", request=self.request)

                elif data_dict["URL"] == "/chat_logs":
                    if "Cookie" in data_dict:
                        user = find_user_cookie(data_dict["Cookie"])
                        if user != "":
                            users = form_dict["collection"].split("_", 1)
                            for u in users:
                                if user == u:
                                    js = database.get_documents(form_dict["collection"])
                                    return new_response(code="200", content=js, contentType="application/json",
                                                 request=self.request)
                                    break


                    return new_response(code="301", location="/login", request=self.request)

                elif data_dict["URL"] == "/image-upload":
                    print()
                elif data_dict["URL"] == "/user_info":
                    if "Cookie" in data_dict:
                        user = find_user_cookie(data_dict["Cookie"])
                        if user != "":
                            query = {"username": form_dict["username"]}
                            user = user_collection.find_one(query)
                            if user is None:
                                return
                            else:
                                new_response(code="200", content=user, contentType="application/json",
                                             request=self.request)
                    return new_response(code="301", location="/login", request=self.request)


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
        sys.stdout.flush()

        server.serve_forever()