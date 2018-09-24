# -*- encoding: utf-8 -*-

from setuptools import setup, find_packages

setup(
    name="dex2call",
    author="Daniel Domínguez",
    author_email="daniel.dominguez@imdea.org",
    url="https://github.com/KuroAku/dex2call",
    version="0.2",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'Click',
        'r2pipe',
        'androguard'
    ],
    license="LICENSE",
    entry_points={
        "console_scripts": [
            "dex2call = dex2call.cli:cli"
        ]
    },
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    description="A simple module to get calls to android.jar from the bytecode"
)
    
