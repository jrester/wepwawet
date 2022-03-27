import os

from setuptools import find_packages, setup


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name="wepwawet",
    version="0.1.0",
    description="policy routing for VPNs",
    author="Jan-Niklas Weghorn",
    author_email="jrester379@gmail.com",
    packages=find_packages(include="wepwawet"),
    requires=read("requirements.txt").splitlines(),
    python_requires=">=3",
    entry_points={
        "console_scripts": ["wepwawet=wepwawet.cli:cli"],
    },
    long_description=read("README.md"),
)
