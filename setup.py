from setuptools import setup

import keybaseapi

from setuptools.command.test import test as TestCommand


class PyTest(TestCommand):
    user_options = [('pytest-args=', 'a', "Arguments to pass to py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = []

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        #import here, cause outside the eggs aren't loaded
        import pytest, sys
        errno = pytest.main(self.pytest_args)
        sys.exit(errno)



setup(
    name='keybaseio-api',
    version=keybaseapi.__version__,
    packages=['keybaseapi'],
    install_requires=[
        "requests",
        "ConfigMaster>=2.3.5",
        "pgp>=0.0.1",
    ],
    tests_require=[
        'pytest',
        'pytest-cov',
        'coverage',
        'coveralls'
    ],
    dependency_links=[
      'https://github.com/mitchellrj/python-pgp/archive/master.zip#egg=pgp-0.0.1'
    ],
    cmdclass = {'test': PyTest},
    url='https://github.com/SkierPGP/keybase-python3',
    license='GPLv3',
    author='Isaac Dickinson',
    author_email='eyesismine@gmail.com',
    description='A keybase.io API for Python 3',
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Security",
        "Topic :: Security :: Cryptography"
    ]
)
