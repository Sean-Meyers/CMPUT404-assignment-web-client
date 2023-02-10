#!/usr/bin/env python3
# coding: utf-8
# Copyright 2023 Abram Hindle, Sean Meyers, https://github.com/tywtyw2002, and https://github.com/treedust
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
        self.unparsed = unparsed_data


    def __getattr__(self, __name: str):
        attr = self.data.get(__name)
        if attr:
            return attr
        else:
            raise AttributeError(f"type object 'ExtractedData' has no attribute '{__name}'.  Available attributes: {self.__str__()}, extracted from {self.unparsed}")
        

    def __str__(self):
        return self.data.__str__()
            

class HTTPClient(object):
    #def get_host_port(self,url):  
    def __init__(self) -> None:
        super().__init__()
        # Set the response parsing regular expression. ... Punny I know.
        self.REsp = re.compile(
            """
            HTTP/(?P<http_ver>\d.\d)[ ](?P<code>\d{3})[ ](?P<reason>[^\r\n]*)(([\r][\n])|[\n])    # Status line
            (?P<headers>([^\r\n]+(([\r][\n])|[\n]){1})*)                                          # Headers
            (([\r][\n])|[\n])
            (?P<body>([^\r\n]*(([\r][\n])|[\n]){0,1})*)                                           # Message Body
            """, re.VERBOSE)
        self.last_response = None
        self.req = '{method} {path} HTTP/1.1\r\n{headers}\r\n{body}\r\n'


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
            headers_end = buffer.find(b'\r\n\r\n')
            if headers_end > 0:
                c_len_header_start = buffer.find(b'Content-Length: ')
                if c_len_header_start > 0:
                    c_len_start = c_len_header_start + 16
                    digit = buffer[c_len_start : 1+c_len_start]
                    c_len = bytearray()
                    i = 1
                    while digit not in b'\r\n':
                        c_len.extend(digit)
                        digit = buffer[c_len_start+i : 1+c_len_start+i]
                        i += 1
                    header_size = headers_end + 4
                    if len(buffer) >= header_size + int(c_len.decode('utf-8')):
                        done = True
                        break
            part = sock.recv(1024)
            print(part)
            if (part):
                buffer.extend(part)
            else:
                done = not part
  
        return buffer.decode('utf-8')
    
    
    @classmethod
    def gimme_port(cls, parse_result: parse.ParseResult):
        if parse_result.port:
            return parse_result.port
        elif parse_result.scheme == 'http':
            return 80
        elif parse_result.scheme == 'https':
            return 443
        else:
            raise Exception("Can't infer port. Provided scheme " +
                                             "isn't http or url is incomplete.")


    def GET(self, url, args=None):
        parse_result = parse.urlparse(url)
        self.connect(parse_result.hostname, self.gimme_port(parse_result))
        with self.socket:
            # self.req format: '{method} {path} HTTP/1.1\r\n{headers}\r\n{body}\r\n'
            self.sendall(self.req.format(method='GET',
                                         path=(parse_result.path if 
                                                    parse_result.path else '/'),
                                         headers=f'Host: {parse_result.hostname}',
                                         body=''))
            response = self.recvall(self.socket)
        self.last_response = ExtractedData(response, self.REsp)

        try:
            body = self.last_response.body
        except AttributeError:
            body = ''

        return HTTPResponse(int(self.last_response.code), body)


    def POST(self, url, args=None):
        parse_result = parse.urlparse(url)
        self.connect(parse_result.hostname, self.gimme_port(parse_result))
        with self.socket:
            headers = 'Host: {host}\r\nContent-Length: {content_length}'
            if args:
                args = parse.urlencode(args)
                content_length = len(args)
                headers = (headers + 
                    '\r\nContent-Type: application/x-www-form-urlencoded\r\n'
                                ).format(host=parse_result.hostname,
                                                  content_length=content_length)
            else:
                args = ''
                headers = headers.format(host=parse_result.hostname,
                                                               content_length=0)
            # self.req format: '{method} {path} HTTP/1.1\r\n{headers}\r\n{body}\r\n'
            self.sendall(self.req.format(method='POST',
                                         path=(parse_result.path if
                                                    parse_result.path else '/'),
                                         headers=headers,
                                         body=args))
            response = self.recvall(self.socket)
        self.last_response = ExtractedData(response, self.REsp)

        return HTTPResponse(int(self.last_response.code), self.last_response.body)


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
