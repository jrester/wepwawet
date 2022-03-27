import os

from setuptools import setup


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name="wepwawet",
    version="0.1.0",
    description="policy routing for VPNs",
    author="Jan-Niklas Weghorn",
    author_email="jrester379@gmail.com",
    packages=["wepwawet"],
    requires=read("requirements.txt").split("\n"),
    scripts=["scripts/wepwawet"],
    long_description=read("README.md"),
)
