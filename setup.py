from setuptools import setup

import keybaseapi

setup(
    name='keybaseio-api',
    version=keybaseapi.__version__,
    packages=['keybaseapi'],
    install_requires=[
        "requests",
        "ConfigMaster>=2.3.5",
        "git+https://github.com/mitchellrj/python-pgp.git",
    ],
    url='https://github.com/SkierPGP/keybase-python3',
    license='GPLv3',
    author='Isaac Dickinson',
    author_email='eyesismine@gmail.com',
    description='A keybase.io API for Python 3'
)
