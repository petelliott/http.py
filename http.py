"""
http.py is a one-file pedagogical HTTP/1.1 server.
Copyright (C) 2021, Peter Elliott <pelliott@serenityos.org>

This program is Copyrighted in U.S., under Seal of Copyright #154085, for a
period of 28 years, and anybody caught runnin it without our permission, will
be mighty good friends of ourn, cause we don’t give a dern. Run it. Study it.
Modify it. Distribute it. We wrote it, that’s all we wanted to do.

- Woodie Guthrie
"""
import io
import datetime
import socket
import threading
import re
import json


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

    def json(self):
        if self.headers.get('Content-Type') != 'application/json':
            raise TypeError(f'Can\'t get json for Content-Type: \
{self.headers.get("Content-Type")}')

        if not self.body:
            return None

        return json.load(self.body)


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


class Handler:
    def __init__(self, method, pathre, function):
        self.method = method
        self.pathre = re.compile(f'^{pathre}/?$')
        self.function = function


class HttpServer:
    def __init__(self):
        self.handlers = []

    def run(self, port=8080):
        sock = socket.create_server(("", port))
        while True:
            try:
                conn, _ = sock.accept()
            except KeyboardInterrupt:
                break

            thread = threading.Thread(
                target=self.client_thread,
                args=(conn.makefile('rw'),))
            thread.start()

    def client_thread(self, f):
        with f:
            req = HttpRequest(f)
            for handler in self.handlers:
                match = handler.pathre.match(req.raw_url)
                if match:
                    try:
                        response = handler.function(req, *match.groups())
                    except Exception as e:
                        print(f"[500] {req.raw_url} -- {str(e)}")
                        HttpResponse(
                            500, {"Content-Type": "text/plain"}, str(e) + '\n'
                        ).write(f)
                        return

                    self.sanitize_response(response).write(f)
                    return
            print(f"[404] {req.raw_url} -- Not Found")
            HttpResponse(
                404, {"Content-Type": "text/plain"}, 'Not Found\n').write(f)

    def sanitize_response(self, response):
        if isinstance(response, HttpResponse):
            return response
        elif isinstance(response, tuple):
            code, headers, body = response
        else:
            code = 200
            headers = {}
            body = response

        if isinstance(body, str):
            headers.setdefault("Content-Type", "text/plain")
        elif isinstance(body, dict) or isinstance(body, list):
            headers.setdefault("Content-Type", "application/json")
            body = json.dumps(body, indent=2) + '\n'

        return HttpResponse(code, headers, body)

    def route(self, method, path):
        def decorator(func):
            self.handlers.append(Handler(method, path, func))
            return func
        return decorator

    def GET(self, path):
        return self.route("GET", path)

    def HEAD(self, path):
        return self.route("GET", path)

    def POST(self, path):
        return self.route("POST", path)

    def PUT(self, path):
        return self.route("PUT", path)

    def DELETE(self, path):
        return self.route("DELETE", path)

    def CONNECT(self, path):
        return self.route("CONNECT", path)

    def OPTIONS(self, path):
        return self.route("OPTIONS", path)

    def TRACE(self, path):
        return self.route("TRACE", path)

    def PATCH(self, path):
        return self.route("PATCH", path)


if __name__ == "__main__":
    server = HttpServer()

    @server.GET("/hello/world")
    def hello_world(request):
        return "hello world\n"

    @server.GET("/hello/(.*)")
    def hello_any(request, name):
        return f"hello {name}\n"

    @server.GET("/json")
    def get_json(request):
        return {
            "json": "data",
            "some": "more"
        }

    @server.GET("/error")
    def error(request):
        raise Exception("oopsie")

    @server.POST("/login")
    def login(request):
        data = request.json()
        if data.get("password") == "jacobsucks":
            return "access granted\n"
        else:
            return (403, {}, "access denied\n")

    server.run()
