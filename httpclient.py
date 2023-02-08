#!/usr/bin/env python3
# coding: utf-8
# Copyright 2016 Abram Hindle, https://github.com/tywtyw2002, and https://github.com/treedust
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Do not use urllib's HTTP GET and POST mechanisms.
# Write your own HTTP GET and POST
# The point is to understand what you have to send and get experience with it

import sys
import socket
import re
# you may use urllib to encode data appropriately
import urllib.parse as parse


def help():
    print("httpclient.py [GET/POST] [URL]\n")


class HTTPResponse(object):
    def __init__(self, code=200, body=""):
        self.code = code
        self.body = body



class ExtractedData(object):
    def __init__(self, unparsed_data: str, compiled_re: re.Pattern):
        super().__init__()
        match = compiled_re.match(unparsed_data)
        self.data = match.groupdict() if match else {}


    def __getattr__(self, __name: str):
        attr = self.data.get(__name)
        if attr:
            return attr
        else:
            raise AttributeError(f"type object 'ExtractedData' has no attribute '{__name}'.  Available attributes: {self.__str__()}")
        

    def __str__(self):
        return self.data.__str__()
            


class HTTPClient(object):
    #def get_host_port(self,url):  
    def __init__(self) -> None:
        super().__init__()
        # Set the response parsing regular expression. ... Punny I know.
        self.REsp = re.compile('HTTP/(?P<http_ver>\d.\d) (?P<code>\d{3}) (?P<reason>[^\r\n]*)((\r\n)|\n)(?P<headers>([^\r\n]*((\r\n)|\n))*((\r\n)|\n))(?P<body>[^\r\n]*((\r\n)|\n){0,1})*')
        self.last_response = None


    def connect(self, host, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))

        return None


    def get_code(self, data):
        if not self.last_response:
            self.last_response = ExtractedData(data, self.REsp)

        return self.last_response.code


    def get_headers(self,data):
        if not self.last_response:
            self.last_response = ExtractedData(data, self.REsp)

        return self.last_response.headers


    def get_body(self, data):
        if not self.last_response:
            self.last_response = ExtractedData(data, self.REsp)
        
        return self.last_response.body
    

    def sendall(self, data):
        self.socket.sendall(data.encode('utf-8'))


    def close(self):
        self.socket.close()


    # read everything from the socket
    def recvall(self, sock):
        buffer = bytearray()
        done = False
        while not done:
            part = sock.recv(1024)
            if (part):
                buffer.extend(part)
            else:
                done = not part
  
        return buffer.decode('utf-8')


    def GET(self, url, args=None):
        parse_result = parse.urlparse(url)
        self.connect(parse_result.hostname, parse_result.port)
        with self.socket:
            self.sendall(f'HTTP/1.1 GET {parse_result.path}\r\n\r\n')
            response = self.recvall(self.socket)
        self.last_response = ExtractedData(response, self.REsp)

        return HTTPResponse(self.last_response.code, self.last_response.body)


    def POST(self, url, args=None):
        code = 500
        body = ""
  
        return HTTPResponse(code, body)


    def command(self, url, command="GET", args=None):
        if (command == "POST"):
            return self.POST( url, args )
        else:
            return self.GET( url, args )
    

if __name__ == "__main__":
    client = HTTPClient()
    command = "GET"
    if (len(sys.argv) <= 1):
        help()
        sys.exit(1)
    elif (len(sys.argv) == 3):
        print(client.command( sys.argv[2], sys.argv[1] ))
    else:
        print(client.command( sys.argv[1] ))
