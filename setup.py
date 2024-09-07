import io
import os

from setuptools import setup


# Taken from https://github.com/pypa/pip/blob/003c7ac56b4da80235d4a147fbcef84b6fbc8248/setup.py#L7-L21
def read(rel_path: str) -> str:
    here = os.path.abspath(os.path.dirname(__file__))
    # intentionally *not* adding an encoding option to open, See:
    #   https://github.com/pypa/virtualenv/issues/201#issuecomment-3145690
    with open(os.path.join(here, rel_path)) as fp:
        return fp.read()


# Taken from https://github.com/pypa/pip/blob/003c7ac56b4da80235d4a147fbcef84b6fbc8248/setup.py#L7-L21
def get_version(rel_path: str) -> str:
    for line in read(rel_path).splitlines():
        if line.startswith("__version__"):
            # __version__ = "0.9"
            delim = '"' if '"' in line else "'"
            return line.split(delim)[1]
    raise RuntimeError("Unable to find version string.")


with io.open("README.md", encoding="utf-8") as f:
    long_description = f.read()

with io.open("requirements.txt", encoding="utf-8") as f:
    requirements = [r for r in f.read().split('\n') if len(r)]

setup(name="bip32",
      # We use the first approach from https://packaging.python.org/en/latest/guides/single-sourcing-package-version
      version=get_version("bip32/__init__.py"),
      description="Minimalistic implementation of the BIP32 key derivation scheme",
      long_description=long_description,
      long_description_content_type="text/markdown",
      url="http://github.com/darosior/python-bip32",
      author="Antoine Poinsot",
      author_email="darosior@protonmail.com",
      license="MIT",
      packages=["bip32"],
      keywords=["bitcoin", "bip32", "hdwallet"],
      install_requires=requirements)
