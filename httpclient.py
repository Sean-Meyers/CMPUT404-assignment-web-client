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
    """
    Represents data extracted from a string.
    
    The data can be retrieved from this
    with .notation.
    E.g. extracted_data = ExtractedData('...some data...', reg_ex)
    print(extracted_data.re_group_name)

    Make sure to import re first.
    """

    def __init__(self, unparsed_data: str, compiled_re: re.Pattern):
        """
        Args:
            unparsed_data (str):
                The data to be extracted and loaded into this instance.

            compiled_re (re.Pattern):
                A compiled regular expression that will match substrings in the
                data to named RE groups. After instantiation, you can use these
                named groups as if they are attributes of your instance!

        See Also:
            RE group names:
                https://docs.python.org/3.8/library/re.html?highlight=scanf#regular-expression-syntax:~:text=in%20a%20group.-,(%3FP%3Cname%3E...),-Similar%20to%20regular
            RE Group Dict:
                https://docs.python.org/3.8/library/re.html?highlight=scanf#regular-expression-syntax:~:text=in%20a%20group.-,(%3FP%3Cname%3E...),-Similar%20to%20regular
        """
        super().__init__()
        match = compiled_re.match(unparsed_data)
        self.data = match.groupdict() if match else {}
        self.unparsed = unparsed_data

    def __getattr__(self, __name: str):
        attr = self.data.get(__name)
        if attr:
            return attr
        else:
            raise AttributeError(
                f"""type object 'ExtractedData' has no attribute '{
                                        __name}'.  Available attributes: {
                             self.__str__()}, extracted from {self.unparsed}""")
        
    def __str__(self):
        return self.data.__str__()
            

class HTTPClient(object): 
    """
    A client for getting and posting to web servers and stuff.

    Instance Attributes:
        self.REsp (re.Pattern):
            For parsing the various fields of an HTTP response.

        self.last_response (ExtractedData):
            The last response in convenient ExtractedData form, try
            last_response.code or something... see, convenient. This mainly
            exists in case you want to reuse some info for a short period.

        self.req (str):
            Format string template for constructing HTTP requests.

        self.socket (socket.socket):
            The socket initialized in self.connect(...), make sure you do "with
            self.socket:" after calling connect(...).
    """

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
        """
        Connect to the given host and port.

        Args:
            host (str):
                The host to connect to.

            port (int):
                The port to connect to. Does not accept strings like 'http',
                must be a number (e.g. 80 for http).
        """
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))


    def get_code(self, data):
        """
        Get the http code from the response in data.

        Args:
            data (str): The HTTP response

        Returns:
            str: String representation of the code. Make sure to call int()!
        """
        if not self.last_response:
            self.last_response = ExtractedData(data, self.REsp)

        return self.last_response.code


    def get_headers(self,data):
        """
        Get the http headers from the response in data.

        Args:
            data (str): The HTTP response

        Returns:
            str: Headers in the http response.
        """
        if not self.last_response:
            self.last_response = ExtractedData(data, self.REsp)

        return self.last_response.headers


    def get_body(self, data):
        """
        Get the http body from the response in data.

        Args:
            data (str): The HTTP response

        Returns:
            str: Body of the http response. The thing after the double CRLF.
        """
        if not self.last_response:
            self.last_response = ExtractedData(data, self.REsp)
        
        return self.last_response.body
    

    def sendall(self, data):
        self.socket.sendall(data.encode('utf-8'))


    def close(self):
        self.socket.close()


    def recvall(self, sock):
        """
        Read everything from the socket.

        Now with new and improved hanging connection eliminator.

        Args:
            sock (socket.socket): The socket to receive data from.

        Returns:
            str: Decoded http response.
        """
        buffer = bytearray()
        done = False
        while not done:
            # ----------------------
            # Find the end of the headers so we can check for content length of
            # the body, then start counting from the beginning of the http body
            # until we've hit that number. At that point, break from the loop
            # so we don't get rekked by a hanging recv().
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
            # ---------------------------
            part = sock.recv(1024)
            if (part):
                buffer.extend(part)
            else:
                done = not part
  
        return buffer.decode('utf-8')
    
    
    @classmethod
    def gimme_port(cls, parse_result: parse.ParseResult):
        """
        ...or else I'll open a can of whoop-exception on you.
        
        urllib.parse.ParseResult won't automatically infer the port from the
        scheme if none is provided explicitely, so we have to use this to do
        that.

        Raises an exception if scheme is not http or https.

        See Also:
            https://docs.python.org/3.8/library/urllib.parse.html#urllib.parse.urlparse

        Return the integer port number.
        """
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
            print(response)
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
            print(response)
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
