# Requires Python 2.7 or Python 3.3+
#
# To get usage information: python repl.py

from __future__ import absolute_import, division, print_function, unicode_literals

import code
import collections
import contextlib
import json
import sys

if (3,3) <= sys.version_info < (4,0):
    import http.client as httplib
    import urllib.parse as urlparse
    unicode = str
elif (2,7) <= sys.version_info < (3,0):
    import httplib
    import urllib as urlparse
    bytes = str
else:
    sys.stderr.write(
        "This program requires Python 2.7+ or 3.3+.  Currently running under Python {}.{}.\n"
        .format(*sys.version_info[:2]))
    sys.exit(1)

def main():
    prog_name, args = sys.argv[0], sys.argv[1:]
    auth_file, repl = parse_args_or_exit(prog_name, sys.stderr, sys.stdout, args)

    try:
        access_token, host_suffix = load_auth_json(auth_file)
    except AuthJsonLoadError as e:
        sys.stderr.write("Error loading <auth-file> \"{}\": {}\n".format(auth_file, e))
        sys.exit(1)

    repl_symbols = dict(
        a=Host(access_token, 'api' + host_suffix),
        c=Host(access_token, 'content' + host_suffix),
        hint=hint,
    )

    print("")
    print("For help, type 'hint'")
    repl(repl_symbols)

class Host(object):
    def __init__(self, access_token, hostname):
        self.access_token = access_token
        self.hostname = hostname

    def __str__(self):
        return "Host({!r})".format(self.hostname)

    @classmethod
    def _make_api_arg(cls, args, kwargs):
        if len(args) == 0:
            if len(kwargs) == 0:
                return False, None
            return True, kwargs
        elif len(args) == 1:
            arg = args[0]
            if len(kwargs) != 0:
                raise AssertionError(
                    "You provided an explicit argument {!r} as well as keyword-style arguments "
                    "{!r}.  You can't provide both.".format(arg, kwargs))
            return True, arg
        else:
            raise AssertionError("Too many non-keyword arguments: {!r}".format(args))

    def rpc(self, function, *args, **kwargs):
        headers = self._copy_headers(kwargs, 'content-type')

        assert '_b' not in kwargs, "Not expecting body value '_b'"

        include_arg, api_arg = self._make_api_arg(args, kwargs)
        if include_arg:
            headers['Content-Type'] = 'application/json'
            body = json.dumps(api_arg, ensure_ascii=False).encode('utf-8')
        else:
            body = b''

        with self._request('POST', function, headers, body=body) as r:
            if r.status == 200:
                return self._handle_json_body(r)
            return self._handle_error(r)

    def up(self, function, *args, **kwargs):
        headers = self._copy_headers(kwargs, 'dropbox-api-arg', 'content-type')

        assert '_b' in kwargs, "Missing body value '_b'"
        body = kwargs.pop('_b')
        assert isinstance(body, bytes), "Expected '_b' to be a bytestring, but got {!r}".format(body)

        include_arg, api_arg = self._make_api_arg(args, kwargs)
        if include_arg:
            headers['Dropbox-API-Arg'] = json.dumps(api_arg, ensure_ascii=True)
        headers['Content-Type'] = 'application/octet-stream'

        with self._request('POST', function, headers, body=body) as r:
            if r.status == 200:
                return self._handle_json_body(r)
            return self._handle_error(r)

    def down(self, function, *args, **kwargs):
        headers = self._copy_headers(kwargs, 'Accept')
        headers['Accept'] = 'application/vnd.dropbox-cors-hack'

        assert '_b' not in kwargs, "Not expecting body value '_b'"

        include_arg, api_arg = self._make_api_arg(args, kwargs)
        if include_arg:
            url_params = {'arg': json.dumps(api_arg, ensure_ascii=False).encode('utf-8')}

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
        url_path = "/2-beta-2/{}".format(urlparse.quote(function))
        if url_params is not None:
            url_path = url_path + '?' + urlparse.urlencode(list(url_params.items()))

        # Py2.7 expects byte strings, Py3+ expects unicode strings.
        if str == bytes:
            method = method.encode('ascii')
            url_path = url_path.encode('ascii')
            headers = {k.encode('ascii'): v.encode('ascii') for k, v in headers.items()}

        c = httplib.HTTPSConnection(self.hostname)
        c.request(method, url_path, body, headers)
        return contextlib.closing(c.getresponse())

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
            r.append(json.dumps(self.result, ensure_ascii=False, indent=4))
        if self.content is not None:
            r.append("<{} bytes> {!r}".format(len(self.content), self.content[:50]))
        return '\n'.join(r)

class StringRepr(object):
    def __init__(self, s): self.s = s
    def __repr__(self): return self.s

hint = StringRepr('\n'.join([
    "",
    "Use 'a' to make requests to the \"api\" server.",
    "Use 'c' to make requests to the \"content\" server.",
    "",
    "Examples:",
    "    a.rpc('files/get_metadata', path='/Camera Uploads')",
    "    c.up('files/upload', path='/faq.txt', mode='add', _b=b'What?')",
    "    c.down('files/download', path='/faq.txt', _h={'If-None-Match': 'W/\"1234\"'})",
    "",
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
        raise AuthJsonLoadError("doesn't contain a JSON object at the top level")

    access_token = auth_json.pop('access_token', None)
    if access_token is None:
        raise AuthJsonLoadError("missing field \"access_token\"")
    elif not isinstance(access_token, unicode):
        raise AuthJsonLoadError("expecting \"access_token\" to be a string");

    host_suffix = auth_json.pop('host_suffix', None)

    if host_suffix is None:
        host_suffix = '.dropboxapi.com'
    elif not isinstance(host_suffix, unicode):
        raise AuthJsonLoadError("expecting \"host_suffix\" to be a string");

    if len(auth_json) > 0:
        raise AuthJsonLoadError("unexpected fields: {}".format(devql(auth_json.keys())))

    return access_token, host_suffix

class AuthJsonLoadError(Exception):
    pass

def devq(s):
    assert isinstance(s, unicode), repr(s)
    return json.dumps(s)

def devql(l):
    return ', '.join(map(devq, l))

def parse_args_or_exit(prog_name, err, out, args):
    remaining = []
    repl_prev = None
    repl_preference = None

    def check_prev(arg):
        if repl_prev is not None:
            err.write("Duplicate/conflicting flags: \"{}\", \"-ri\".\n".format(repl_prev, arg))
            err.write("Run with \"--help\" for more information.\n")
            sys.exit(1)
        return arg

    for i in range(len(args)):
        arg = args[i]
        if arg.startswith('-'):
            if arg == '-ri':
                repl_prev = check_prev(arg)
                repl_preference = 'ipython'
            elif arg == '-rs':
                repl_prev = check_prev(arg)
                repl_preference = 'standard'
            elif arg in ('-h', '--help'):
                if len(args) != 1:
                    err.write("\"{}\" must be used by itself.\n".format(arg))
                    err.write("Run with \"--help\" for more information.\n")
                    sys.exit(1)
                print_usage(prog_name, out)
                sys.exit(0)
            else:
                err.write("Invalid option: {}.\n".format(devq(arg)))
                err.write("Run with \"--help\" for more information.\n")
                sys.exit(1)
        else:
            remaining.append(arg)

    if len(remaining) == 0:
        err.write("Missing <auth.json> argument.\n")
        err.write("Run with \"--help\" for more information.\n")
        sys.exit(1)

    if len(remaining) != 1:
        err.write("Expecting one non-option argument, got {}: {}"
                  .format(len(remaining), devql(remaining)))
        err.write("Run with \"--help\" for more information.\n")
        sys.exit(1)

    auth_file = remaining[0]

    # Load the appropriate REPL.
    if repl_preference == 'ipython':
        # IPython required.
        repl = try_creating_ipython_repl(err)
        if repl is None:
            err.write("To fall back to the standard Python REPL, don't use the \"-ri\" option.\n")
            sys.exit(1)
    elif repl_preference == 'standard':
        # Use the standard REPL.
        repl = standard_repl
    elif repl_preference is None:
        # Try IPython.  If that fails, use the standard REPL.
        repl = try_creating_ipython_repl(None)
        if repl is None:
            err.write("Unable to load IPython; falling back to the standard Python REPL.\n")
            err.write("(Run with \"-ri\" to see details; run with \"-rs\" to hide this warning.)\n")
            repl = standard_repl
    else:
        raise AssertionError("bad value: {!r}".format(repl_preference))

    return auth_file, repl

def standard_repl(symbols):
    code.interact(banner='', local=symbols)

def try_creating_ipython_repl(err):
    try:
        import IPython
        if IPython.__version__.startswith('0.'):
            if err is not None:
                err.write("The current IPython version is {}, but this script requires at least 1.0.\n"
                          .format(IPython.__version__))
                err.write("To upgrade IPython, try: \"sudo pip install ipython --upgrade\"\n")
            return None

        def repl(symbols):
            ipython = IPython.terminal.interactiveshell.TerminalInteractiveShell(user_ns=symbols)
            ipython.confirm_exit = False
            ipython.interact()
        return repl

    except ImportError as e:
        if err is not None:
            err.write("Unable to import \"IPython\": {}\n".format(e))
            err.write("To install IPython, try: \"sudo pip install ipython\"\n")
        return None

def print_usage(prog_name, out):
    out.write("Usage: {} [options...] <auth.json>\n")
    out.write("\n")
    out.write("    <auth-json>: See ReadMe.md for information on how to create this file.\n")
    out.write("\n")
    out.write("    -ri: Use IPython for the REPL.\n")
    out.write("    -rs: Use the standard Python REPL.\n")
    out.write("\n")

if __name__ == '__main__':
    main()
