# Dropbox API v2 REPL

A Python REPL that lets you make calls to the Dropbox API v2.

1. Get a Dropbox API access token.  You can use the Dropbox website to [get an access token for your own account](https://blogs.dropbox.com/developers/2014/05/generate-an-access-token-for-your-own-account/).

2. Put the access token in a file called `auth.json`:

    ```json
    {
        "access_token": "<insert-access-token-here>"
    }
    ```

3. Run the command: `python repl.py auth.json`.

    ```
    For help, type 'hint'

    In [1]: hint
    Out[1]:

    Use 'a' to make requests to the "api" server.
    Use 'c' to make requests to the "content" server.

    Examples:
        a.rpc('files/get_metadata', path='/Camera Uploads')
        c.up('files/upload', path='/faq.txt', mode='add', _b=b'What?')
        c.down('files/download', path='/faq.txt', _h={'If-None-Match': 'W/"1234"'})
    ```
