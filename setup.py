#!/usr/bin/env python

version = '1.1.2'

sdict = {
    'name' : 'simpleacl',
    'version' : version,
    'description' : 'Simple Access Control list for Python',
    'long_description' : 'Simple Access Control list for Python that includes wsgi middleware.',
    'url': 'https://github.com/kyleterry/simpleacl-py',
    'author' : 'Kyle Terry',
    'author_email' : 'kyle@kyleterry.com',
    'maintainer' : 'Ivan Zakrevsky',
    'maintainer_email' : 'ivzak@yandex.ru',
    'keywords' : ['acl', 'simpleacl', 'access control list', 'auth list'],
    'license' : 'LGPLv2+ License',
    'packages' : ['simpleacl'],
    'test_suite' : 'tests.all_tests',
    'install_requires': [
        'nose',
        'coverage',
    ],
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
