# Requires Python 2.7 or Python 3.3+
#
# To get usage information: python repl.py

from __future__ import absolute_import, division, print_function, unicode_literals

import collections
import contextlib
import json
import sys
import types

if (3,4) <= sys.version_info < (4,0):
    import http.client as httplib
    import urllib.parse as urlparse
elif (2,7) <= sys.version_info < (3,0):
    import httplib
    import urllib as urlparse
    bytes = str
else:
    sys.stderr.write(
        "This program requires Python 2.7+ or 3.3+.  Currently running under Python {}.{}.\n"
        .format(*sys.version_info[:2]))
    sys.exit(1)

try:
    import IPython
except ImportError as e:
    sys.stderr.write("Unable to import \"IPython\": {}\n".format(e))
    sys.stderr.write("This script requires IPython to run.\n")
    sys.stderr.write("To install IPython, try: sudo pip install ipython\n")
    sys.exit(1)

if IPython.__version__.startswith('0.'):
    sys.stderr.write("Your current IPython version is {}.\n".format(IPython.__version__))
    sys.stderr.write("This script requires 1.0 or greater.\n")
    sys.stderr.write("To upgrade IPython, try: sudo pip install ipython --upgrade\n")
    sys.exit(1)

def main():
    prog_name, args = sys.argv[0], sys.argv[1:]

    if len(args) == 0:
        sys.stdout.write('\n')
        sys.stdout.write("Usage: python {} <auth.json>\n".format(prog_name))
        sys.stdout.write('\n')
        sys.stdout.write("  <auth.json>: See ReadMe.md for information on how ot create this file.\n")
        sys.stdout.write('\n')
        sys.exit(1)

    if len(args) != 1:
        sys.stderr.write("Expecting exactly one argument.  Run with no arguments for help.\n")
        sys.exit(1)

    auth_file = args[0]

    try:
        access_token, host_suffix = load_auth_json(auth_file)
    except AuthJsonLoadError as e:
        sys.stderr.write("Error loading <auth-file> \"{}\": {}\n".format(auth_file, e))
        sys.exit(1)

    ipython_symbols = dict(
        a=Host(access_token, 'api' + host_suffix),
        c=Host(access_token, 'api-content' + host_suffix),
        hint=hint,
    )
    ipython_module = types.ModuleType(str('v2'))

    ipython = IPython.terminal.embed.InteractiveShellEmbed(display_banner=False)
    ipython.confirm_exit = False

    print("")
    print("For help, type 'hint'")
    ipython.mainloop(local_ns=ipython_symbols, module=ipython_module)

class Host(object):
    def __init__(self, access_token, hostname):
        self.access_token = access_token
        self.hostname = hostname

    def rpc(self, function, **kwargs):
        headers = self._copy_headers(kwargs, 'content-type')

        assert '_b' not in kwargs, "Not expecting body value '_b'"

        headers['Content-Type'] = 'application/json'
        body = json.dumps(kwargs, ensure_ascii=False).encode('utf-8')

        with self._request('POST', function, headers, body=body) as r:
            if r.status == 200:
                return self._handle_json_body(r)
            return self._handle_error(r)

    def up(self, function, **kwargs):
        headers = self._copy_headers(kwargs, 'dropbox-api-arg', 'content-type')

        assert '_b' in kwargs, "Missing body value '_b'"
        body = kwargs.pop('_b')
        assert isinstance(body, bytes), "Expected '_b' to be a bytestring, but got {!r}".format(body)

        headers['Dropbox-API-Arg'] = json.dumps(kwargs, ensure_ascii=True)
        headers['Content-Type'] = 'application/octet-stream'

        with self._request('POST', function, headers, body=body) as r:
            if r.status == 200:
                return self._handle_json_body(r)
            return self._handle_error(r)

    def down(self, function, **kwargs):
        headers = self._copy_headers(kwargs, 'Accept')
        headers['Accept'] = 'application/vnd.dropbox-cors-hack'

        assert '_b' not in kwargs, "Not expecting body value '_b'"

        url_params = {'arg': json.dumps(kwargs, ensure_ascii=False).encode('utf-8')}

        with self._request('GET', function, headers, url_params=url_params) as r:
            if r.status == 200:
                result_str = r.getheader('Dropbox-API-Result').encode('ascii')
                assert result_str is not None, "Missing Dropbox-API-Result response header."
                result = json_loads_ordered(result_str)
                return Response(200, extract_headers(r, "ETag", "Cache-Control"), result, r.read())
            if r.status == 304:
                return Response(304, extract_headers(r, "ETag", "Cache-Control"))
            return self._handle_error(r)

    def _copy_headers(self, kwargs, *disallowed):
        headers = kwargs.pop('_h', {})
        assert isinstance(headers, dict), "Expected '_h' to be a 'dict', got {!r}".format(headers)
        disallowed = disallowed + ('authorization',)
        for key in headers:
            assert key.lower() not in disallowed, "Disallowed header: {!r}".format(key)
        headers = headers.copy()
        headers['Authorization'] = 'Bearer {}'.format(self.access_token)
        return headers

    def _request(self, method, function, headers, url_params=None, body=None):
        url_path = "/2-beta/{}".format(urlparse.quote(function))
        if url_params is not None:
            url_path = url_path + '?' + urlparse.urlencode(list(url_params.items()))

        c = httplib.HTTPSConnection(self.hostname)
        c.request(method, url_path, body, headers)
        return contextlib.closing(c.getresponse())

    def _url_path(self, function):
        return "/2-beta/{}".format(urlparse.quote(function))

    def _handle_json_body(self, r):
        ct = r.getheader('Content-Type').encode('ascii')
        assert ct == b'application/json', "Bad Content-Type: {!r}".format(ct)
        return Response(r.status, {}, json_loads_ordered(r.read()))

    def _handle_error(self, r):
        if r.status == 400:
            ct = r.getheader('Content-Type').encode('ascii')
            assert ct == b'text/plain; charset=utf-8', "Bad Content-Type: {!r}".format(ct)
            return Response400(r.read().decode('utf-8'))
        if r.status in (401, 403, 404, 409):
            return self._handle_json_body(r)
        if r.status == 429:
            return Response(r.status, extract_headers(r, "Retry-After"))
        if r.status in (500, 503):
            return Response(r.status, {})
        raise AssertionError("unexpected response code: {!r}, {!r}".format(r.status, r.read()))

def json_loads_ordered(s):
    assert isinstance(s, bytes), repr(s)
    u = s.decode('utf-8')
    return json.JSONDecoder(object_pairs_hook=collections.OrderedDict).decode(u)

def extract_headers(r, *targets):
    s = set(t.lower() for t in targets)
    return {k: v.encode('ascii') for k, v in r.getheaders() if k.lower() in s}

class Response400(object):
    def __init__(self, error_message):
        self.error_message = error_message

    def __repr__(self):
        return "HTTP 400: {}".format(self.error_message)

class Response(object):
    def __init__(self, status, headers, result=None, content=None):
        self.status = status
        self.headers = headers
        self.result = result
        self.content = content

    def __repr__(self):
        r = ["HTTP {}".format(self.status)]
        for key, value in self.headers.items():
            r.append("{}: {!r}".format(key, value))
        if self.result is not None:
            r.append(json.dumps(self.result, indent=4))
        if self.content is not None:
            r.append("<{} bytes> {!r}".format(len(self.content), self.content[:50]))
        return '\n'.join(r)

class StringRepr(object):
    def __init__(self, s): self.s = s
    def __repr__(self): return self.s

hint = StringRepr('\n'.join([
    "",
    "Use 'a' to make requests to the \"api\" server.",
    "Use 'c' to make requests to the \"api-content\" server.",
    "",
    "Examples:",
    "    a.rpc('files/get_metadata', path='/Camera Uploads')",
    "    c.up('files/upload', path='/faq.txt', mode='add', _b=b'What?')",
    "    c.down('files/download', path='/faq.txt', _h={'If-None-Match': 'W/\"1234\"'})",
]))

def load_auth_json(auth_file):
    try:
        with open(auth_file, 'rb') as f:
            data = f.read()
    except OSError as e:
        raise AuthJsonLoadError("unable to read file: {}".format(e))

    try:
        auth_json = json.loads(data.decode('utf-8'))
    except UnicodeDecodeError as e:
        raise AuthJsonLoadError("invalid UTF-8: {}".format(e))
    except ValueError as e:
        raise AuthJsonLoadError("not valid JSON: {}".format(e))

    if not isinstance(auth_json, dict):
        raise LoadError("doesn't contain a JSON object at the top level")

    access_token = auth_json.get('access_token')
    if access_token is None:
        raise AuthJsonLoadError("missing field \"access_token\"")

    host = auth_json.get('host')
    if host == 'dropbox.com':
        host = None

    if host is None:
        host_suffix = '.dropbox.com'
    else:
        host_suffix = '-' + host

    return access_token, host_suffix

class AuthJsonLoadError(Exception):
    pass

if __name__ == '__main__':
    main()
