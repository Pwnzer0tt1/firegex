import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="fgex",
    version="0.0.1",
    author="Pwnzer0tt1",
    author_email="pwnzer0tt1@poliba.it",
    py_modules=["fgex"],
    install_requires=["firegex"],
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
