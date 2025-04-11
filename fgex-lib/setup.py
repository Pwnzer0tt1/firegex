import setuptools

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
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.10',
)
