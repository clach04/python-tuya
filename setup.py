#!/usr/bin/env python

from distutils.core import setup

setup(name='python-tuya',
	version='0.1',
        packages=['pytuya'],
	description='Python implementation of the Tuya protocol',
	author='clach04',
	url='https://github.com/clach04/python-tuya',
	install_requires=['pycrypto >= 2.6'],
	)
