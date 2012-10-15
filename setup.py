#!/usr/bin/env python

"""
@file setup.py
@author Ivan Zakrevsky
@date 3/15/2010
@brief Setuptools configuration for simpleacl
"""

version = '1.1.0'

sdict = {
    'name' : 'simpleacl',
    'version' : version,
    'description' : 'Simple Access Control list for Python',
    'long_description' : 'Simple Access Control list for Python that includes wsgi middleware.',
    'url': 'http://github.com/EvoTech/simpleacl-py',
    'download_url' : 'http://cloud.github.com/downloads/EvoTech/simpleacl-py/simpleacl-{0}.tar.gz'.format(version),
    'author' : 'Ivan Zakrevsky',
    'author_email' : 'ivzak@yandex.ru',
    'maintainer' : 'Ivan Zakrevsky',
    'maintainer_email' : 'ivzak@yandex.ru',
    'keywords' : ['acl', 'simpleacl', 'access control list', 'auth list'],
    'license' : 'LGPLv2+ License',
    'packages' : ['simpleacl'],
    'test_suite' : 'tests.all_tests',
    'classifiers' : [
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)',
        'Operating System :: OS Independent',
        'Programming Language :: Python'],
}

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup
    
setup(**sdict)
