#!/usr/bin/env python

"""
@file setup.py
@author Kyle Terry
@date 3/15/2010
@brief Setuptools configuration for simpleacl
"""

version = '1.0.0'

sdict = {
    'name' : 'simpleacl',
    'version' : version,
    'description' : 'Simple Access Control list for Python',
    'long_description' : 'Simple Access Control list for Python that includes wsgi middleware.',
    'url': 'http://github.com/kyleterry/simpleacl-py',
    'download_url' : 'http://cloud.github.com/downloads/kyleterry/simpleacl-py/simpleacl-%s.tar.gz' % version,
    'author' : 'Kyle Terry',
    'author_email' : 'kyle@kyleterry.com',
    'maintainer' : 'Kyle Terry',
    'maintainer_email' : 'kyle@kyleterry.com',
    'keywords' : ['acl', 'simpleacl', 'access control list', 'auth list'],
    'license' : 'GPL',
    'packages' : ['simpleacl'],
    'test_suite' : 'tests.all_tests',
    'classifiers' : [
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python'],
}

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup
    
setup(**sdict)

