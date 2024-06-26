#! /usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

#
# NOTE - this file appears to be obsoleted by pyproject.toml. It's still present in
# upstream too, but appears to be ignored due to poetry being used as build tool.
#

setup(
    name='maykin-python3-saml',
    version='1.16.0.post0',  # can't use PEP 440 local versions with PyPI
    description='Saml Python Toolkit. Add SAML support to your Python software using this library',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ],
    author='OneLogin, Maykin Media',
    author_email='support@maykinmedia.nl',
    license='MIT',
    url='https://github.com/maykinmedia/python3-saml@maykin',
    packages=['onelogin', 'onelogin/saml2'],
    include_package_data=True,
    package_data={
        'onelogin/saml2/schemas': ['*.xsd'],
    },
    package_dir={
        '': 'src',
    },
    test_suite='tests',
    install_requires=[
        'lxml>=4.7.1',
        'isodate>=0.6.1',
        'xmlsec>=1.3.9',
        'requests>=2.24.0',
        'pyOpenSSL>=19.1.0',
    ],
    dependency_links=['http://github.com/mehcode/python-xmlsec/tarball/master'],
    extras_require={
        'test': (
            'coverage>=4.5.2',
            'freezegun>=0.3.11, <=1.1.0',
            # 'pylint>=1.9.4',
            'flake8>=3.6.0, <=5.0.0',
            'pytest>=4.6',
            'responses>=0.12.0',
            'requests-mock>=1.9.3',
        ),
    },
    keywords='saml saml2 sso xmlsec federation identity',
)
