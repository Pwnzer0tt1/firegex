"""What a published wheel has to do, checked where nothing else is installed.

`cibuildwheel` runs this against each built wheel in a clean environment, which is the
one property that matters here: it is the only place in the whole pipeline that looks
like a user's machine rather than a developer's. The error path of the parser binding
once imported `pyllhttp` — archived, not a dependency, present on both machines this was
written on and on no other — and every check we had passed anyway, because every check
we had parsed *valid* traffic.

So: a good exchange, a bad one, and the exception that names it.
"""

import sys

from firegex import _llhttp

response = _llhttp.Response()
response.execute(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
assert response.status_code == 404, response.status_code

assert _llhttp.Request.__module__ == "firegex._llhttp", _llhttp.Request.__module__
assert _llhttp.Error.__module__ == "firegex._llhttp", _llhttp.Error.__module__

request = _llhttp.Request()
try:
    request.execute(b"NOTAMETHOD / HTTP/1.1\r\n\r\n")
except _llhttp.InvalidMethodError as error:
    assert "method" in str(error).lower(), error
else:
    raise AssertionError("a malformed request was parsed without complaint")

# Not a detail: borrowing the exception from somewhere else is exactly what used to
# happen, and it only ever worked where that somewhere else happened to be installed.
assert "pyllhttp" not in sys.modules, "the parser reached for pyllhttp"

print(f"llhttp {_llhttp.version} ok on {sys.implementation.name} {sys.version.split()[0]}")
