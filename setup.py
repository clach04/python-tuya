import codecs
import os
import sys
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

import pytuya


if len(sys.argv) <= 1:
    print("""
Suggested setup.py parameters:
    * build
    * install
    * sdist  --formats=zip
    * sdist  # NOTE requires tar/gzip commands
""")

here = os.path.abspath(os.path.dirname(__file__))

with codecs.open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='pytuya',
    author=pytuya.__author__,
    version=pytuya.__version__,
    description='Python interface to ESP8266MOD WiFi smart devices from Shenzhen Xenon',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/clach04/python-tuya',
    author_email='',
    license='MIT',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Home Automation',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Topic :: Home Automation',
    ],
    keywords='home automation',
    packages=['pytuya'],
    platforms='any',
    install_requires=[
          'pyaes',  # NOTE this is optional, AES can be provided via PyCrypto or PyCryptodome
      ],
)
