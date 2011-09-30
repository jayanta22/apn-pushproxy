#!/usr/bin/python

from setuptools import setup


setup(
	name="apn-pushproxy",
	version="0.1",
	author="Piotr Duda, Karol Kuczmarski",
	author_email="piotr.duda@polidea.pl, karol.kuczmarski@polidea.pl",
	url="http://code.google.com/a/apn-pushproxy",
	license="MIT",
	description="HTTP proxy for Apple Push Notification Service",

	requires=['Flask'],

	classifiers = [
		"Development Status :: 3 - Alpha",
		"Environment :: Console",
		"Intended Audience :: Developers",
		"Intended Audience :: System Administrators",
		"License :: OSI Approved :: BSD License",
		"Operating System :: OS Independent",
		"Programming Language :: Python",
		"Programming Language :: Python :: 2.7",
		"Topic :: Communications",
		"Topic :: Internet",
		"Topic :: Internet :: WWW/HTTP",
		"Topic :: Internet :: WWW/HTTP :: HTTP Servers",
		"Topic :: Internet :: WSGI",
		"Topic :: Internet :: WSGI :: Application",
		"Topic :: Utilities",
	],

	scripts = ['apn_pushproxy.py'],
)
