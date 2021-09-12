"""
http.py is a one-file pedagogical HTTP/1.1 server implementation.
Copyright (C) 2021, Peter Elliott <pelliot@serenityos.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
import io
import datetime
import socket
import threading


class ContentLengthStream(io.TextIOBase):
    def __init__(self, f, content_length):
        self.f = f
        self.content_length = content_length

    def read(self, size=-1):
        if size == -1:
            str = self.f.read(self.content_length)
        else:
            str = self.f.read(max(size, self.content_length))

        self.content_length -= len(str)
        return str


class HttpMessage:
    def __init__(self):
        self.headers = {}
        self.body = None

    def read_headers(self, f):
        for line in f:
            if line.isspace():
                break

            name, value = line.split(':', maxsplit=1)
            self.headers[name] = value.strip()

    def write_headers(self, f):
        for name, value in self.headers.items():
            f.write(f'{name}: {value}\r\n')


class HttpRequest(HttpMessage):
    def __init__(self, f=None):
        super().__init__()
        if f:
            self.read_from(f)

    def read_from(self, f):
        self.read_request_line(f)
        self.read_headers(f)
        self.maybe_read_request_body(f)

    def read_request_line(self, f):
        self.method, self.raw_url, self.http_version = f.readline().split()
        # TODO: parse the url

    def maybe_read_request_body(self, f):
        if 'Content-Length' in self.headers:
            self.body = ContentLengthStream(
                f, int(self.headers['Content-Length']))
        # TODO: support chunked encoding


reason_phrases = {
    100: "Continue",
    101: "Switching Protocols",
    200: "OK",
    201: "Created",
    202: "Accepted",
    203: "Non-Authoritative Information",
    204: "No Content",
    205: "Reset Content",
    206: "Partial Content",
    300: "Multiple Choices",
    301: "Moved Permanently",
    302: "Found",
    303: "See Other",
    304: "Not Modified",
    305: "Use Proxy",
    307: "Temporary Redirect",
    400: "Bad Request",
    401: "Unauthorized",
    402: "Payment Required",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    407: "Proxy Authentication Required",
    408: "Request Time-out",
    409: "Conflict",
    410: "Gone",
    411: "Length Required",
    412: "Precondition Failed",
    413: "Request Entity Too Large",
    414: "Request-URI Too Large",
    415: "Unsupported Media Type",
    416: "Requested range not satisfiable",
    417: "Expectation Failed",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Time-out",
    505: "HTTP Version not supported",
}


class HttpResponse(HttpMessage):
    def __init__(self, code, headers, body=None):
        super().__init__()
        self.status_code = code
        self.headers = headers
        self.body = body
        self.autofill_headers()

    def autofill_headers(self):
        self.headers.setdefault("Server", "http.py/1.0")
        self.headers.setdefault(
            "Date", datetime.datetime.now().astimezone().strftime(
                "%a, %d %b %Y %H:%M:%S %Z"))

        if self.body:
            self.headers.setdefault("Content-Length", len(self.body))

    def write_status_line(self, f):
        f.write(f'HTTP/1.1 {self.status_code} \
{reason_phrases.get(self.status_code, "")}\r\n')

    def write(self, f):
        self.write_status_line(f)
        self.write_headers(f)
        f.write('\r\n')
        if self.body:
            f.write(self.body)


def handle_client(f):
    HttpRequest(f)
    HttpResponse(200, {}, 'it works lol\n').write(f)
    f.close()


def run(port=8080):
    sock = socket.create_server(("", port))
    while True:
        try:
            conn, _ = sock.accept()
        except KeyboardInterrupt:
            break

        thread = threading.Thread(
            target=handle_client,
            args=(conn.makefile('rw'),))
        thread.start()


if __name__ == "__main__":
    run()
    print("shutting down")
