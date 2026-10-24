"""Local lab for the raijin-fuzz benchmark: small websites on 127.0.0.1, one process.

Each argument is port=kind:

  catchall  a noisy site that answers 200 to every path it does not know, with a "not found" page that
            echoes the path (so each soft-404 has a different size), and 403 to every unknown .php
            (a WAF-style block, always the same page). A few paths are real: /admin redirects to the
            login, /login, /.git/HEAD, /backup.zip, /robots.txt, an /api that answers 401 and a
            /server-status that answers its own 403.
  app       a normal site: unknown paths are 404 (ffuf's default matcher skips them). Real paths:
            directories that redirect to add a slash, an .env, a .git/config, SQL and tar backups, a
            config .bak, phpinfo, a 401 API, 403 .htaccess/.htpasswd/server-status, a 500, a slow
            report (1.5 s), a JSON swagger file and plain pages.

usage: python3 lab.py 19200=catchall 19201=app      (LAB_LOG=1 logs each request to stderr)
"""
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

PAGE = """<!DOCTYPE html>
<html><head><title>{title}</title></head>
<body><nav><a href="/">Home</a> <a href="/about">About</a></nav>
<h1>{title}</h1>
{body}
</body></html>
"""

SOFT404 = """<!DOCTYPE html>
<html><head><title>Not found</title></head>
<body><h1>Sorry</h1>
<p>The page {path} does not exist on this server.</p>
</body></html>
"""

WAF = "<html><body><h1>403 Forbidden</h1><p>Request blocked by the web application firewall.</p></body></html>\n"


def page(title, body=""):
    return PAGE.format(title=title, body=body)


CATCHALL = {
    "/admin": (302, {"Location": "/login?next=/admin"}, ""),
    "/login": (200, {}, page("Sign in", '<form method="post"><input name="user"><input name="password" type="password"></form>')),
    "/.git/HEAD": (200, {"Content-Type": "text/plain"}, "ref: refs/heads/main\n"),
    "/backup.zip": (200, {"Content-Type": "application/zip"}, "PK\x03\x04" + "x" * 300),
    "/robots.txt": (200, {"Content-Type": "text/plain"}, "User-agent: *\nDisallow: /admin\n"),
    "/api": (401, {"Content-Type": "application/json", "WWW-Authenticate": "Bearer"}, '{"error":"unauthorized"}'),
    "/server-status": (403, {}, "<html><body><h1>Forbidden</h1><p>You don't have permission to access this resource.</p></body></html>\n"),
}

APP = {
    "/.env": (200, {"Content-Type": "text/plain"}, "APP_ENV=production\nDB_HOST=db.internal\nDB_PASSWORD=lab-not-a-secret\n"),
    "/.git/config": (200, {"Content-Type": "text/plain"}, '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = git@git.lab.test:app/app.git\n'),
    "/.htaccess": (403, {}, "<html><body><h1>Forbidden</h1></body></html>\n"),
    "/.htpasswd": (403, {}, "<html><body><h1>Forbidden</h1></body></html>\n"),
    "/server-status": (403, {}, "<html><body><h1>Forbidden</h1></body></html>\n"),
    "/backup.sql": (200, {"Content-Type": "application/sql"}, "-- dump\nCREATE TABLE users (id int, email text);\n" * 20),
    "/backup.tar.gz": (200, {"Content-Type": "application/gzip"}, "\x1f\x8b" + "y" * 900),
    "/config.php.bak": (200, {"Content-Type": "text/plain"}, "<?php $db_pass = 'lab-not-a-secret'; ?>\n"),
    "/phpinfo.php": (200, {}, page("phpinfo()", "<table><tr><td>PHP Version</td><td>8.1.2</td></tr></table>")),
    "/swagger.json": (200, {"Content-Type": "application/json"}, '{"openapi":"3.0.0","paths":{"/api/v1/users":{},"/api/v1/admin":{}}}'),
    "/api": (401, {"Content-Type": "application/json"}, '{"error":"missing token"}'),
    "/dashboard": (302, {"Location": "/login"}, ""),
    "/login": (200, {}, page("Sign in", '<form method="post"><input name="user"><input name="password" type="password"></form>')),
    "/debug": (500, {}, page("Internal Server Error", "<pre>Traceback (most recent call last): ...</pre>")),
    "/report": (200, {}, page("Monthly report", "<p>Generated on demand.</p>")),
    "/about": (200, {}, page("About", "<p>We make things.</p>")),
    "/contact": (200, {}, page("Contact", "<p>Write to us.</p>")),
    "/index.html": (200, {}, page("Home", "<p>Welcome.</p>")),
    "/robots.txt": (200, {"Content-Type": "text/plain"}, "User-agent: *\nDisallow: /backup.sql\n"),
}
APP_DIRS = {"admin", "backup", "uploads", "images", "css", "js", "static"}
SLOW = {"/report": 1.5}


class Handler(BaseHTTPRequestHandler):
    kind = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        if os.environ.get("LAB_LOG"):
            sys.stderr.write("%s %s\n" % (self.kind, fmt % args))

    def send(self, status, headers, body):
        data = body.encode("latin-1")
        self.send_response(status)
        headers = dict(headers)
        if "Content-Type" not in headers and "Location" not in headers:
            headers["Content-Type"] = "text/html; charset=utf-8"
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlsplit(self.path).path
        if self.kind == "catchall":
            if path in CATCHALL:
                return self.send(*CATCHALL[path])
            if path.endswith(".php"):
                return self.send(403, {}, WAF)
            return self.send(200, {}, SOFT404.format(path=path))
        if path.rstrip("/").lstrip("/") in APP_DIRS:
            if not path.endswith("/"):
                return self.send(301, {"Location": path + "/"}, "")
            return self.send(200, {}, page("Index of " + path, "<ul></ul>"))
        if path in APP:
            time.sleep(SLOW.get(path, 0))
            return self.send(*APP[path])
        return self.send(404, {}, page("404 Not Found"))


def serve(port, kind):
    handler = type("H_" + kind, (Handler,), {"kind": kind})
    ThreadingHTTPServer(("127.0.0.1", port), handler).serve_forever()


if __name__ == "__main__":
    threads = []
    for arg in sys.argv[1:]:
        port, kind = arg.split("=", 1)
        t = threading.Thread(target=serve, args=(int(port), kind), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
