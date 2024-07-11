import io

from setuptools import setup

with io.open("README.md", encoding="utf-8") as f:
    long_description = f.read()

with io.open("requirements.txt", encoding="utf-8") as f:
    requirements = [r for r in f.read().split("\n") if len(r)]

with io.open("bip32/__version__.py", encoding="utf-8") as f:
    exec(f.read())

setup(
    name="bip32",
    version=__version__,
    description="Minimalistic implementation of the BIP32 key derivation scheme",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="http://github.com/darosior/python-bip32",
    author="Antoine Poinsot",
    author_email="darosior@protonmail.com",
    license="MIT",
    packages=["bip32"],
    keywords=["bitcoin", "bip32", "hdwallet"],
    install_requires=requirements,
)
