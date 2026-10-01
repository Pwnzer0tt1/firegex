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

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open('requirements.txt', 'r', encoding='utf-8') as f:
    required = [ele.strip() for ele in f.read().splitlines() if not ele.strip().startswith("#") and ele.strip() != ""]

VERSION = "{{VERSION_PLACEHOLDER}}"

setuptools.setup(
    name="firegex",
    version= VERSION if "{" not in VERSION else "0.0.0", #uv pip install -U . --no-cache-dir for testing
    author="Pwnzer0tt1",
    author_email="pwnzer0tt1@poliba.it",
    scripts=["fgex"],
    py_modules=["firegex"],
    install_requires=required,
    include_package_data=True,
    description="Firegex client",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pwnzer0tt1/firegex",
    packages=setuptools.find_packages(),
    ext_modules=[LLHTTP],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
    ],
    python_requires='>=3.10',
)
