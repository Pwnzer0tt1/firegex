import setuptools

# The HTTP parser, built from source that ships with this package.
#
# It is llhttp — the parser Node uses — behind a binding that used to live in its own
# package, `pyllhttp`. Three things made vendoring it the only arrangement that works:
# the package was archived; every alternative binding with prebuilt wheels fails to load
# in the subinterpreters `cpproxy` runs filters in (they need
# `Py_MOD_PER_INTERPRETER_GIL_SUPPORTED`, which this declares and `httptools` does not);
# and binding the system `libllhttp` through ctypes would mean `pip install firegex`
# assuming a package the user had installed beforehand.
#
# So the C comes with the source, and the release workflow builds wheels for every
# platform it can. Where no wheel matches, pip compiles this — which needs a C toolchain,
# and is the deliberate trade: compiling is a thing pip knows how to do, assuming a
# system library is not.
LLHTTP = setuptools.Extension(
    "firegex._llhttp",
    sources=["llhttp/llhttp_module.c", "llhttp/lib/llhttp.c",
             "llhttp/lib/http.c", "llhttp/lib/api.c"],
    include_dirs=["llhttp/lib"],
    language="c",
    extra_compile_args=["-O3"],
)

# Everything else about the package is in pyproject.toml. The version stays here because
# the release workflow writes the tag over the placeholder, which is not a valid version
# until it has.
VERSION = "{{VERSION_PLACEHOLDER}}"

setuptools.setup(
    version=VERSION if "{" not in VERSION else "0.0.0", #uv pip install -U . --no-cache-dir for testing
    ext_modules=[LLHTTP],
)
