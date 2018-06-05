#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

setup(
    name='cerespacketexploder',
    version='2.0.0',
    description='Python library for extracting observables from pcap.',
    long_description='',
    author='Rémi ALLAIN',
    author_email='rallain@cyberprotect.fr',
    maintainer='Rémi ALLAIN',
    url='https://github.com/Cyberprotect/Ceres-Packet-Exploder',
    license='Apache 2.0',
    packages=find_packages(),
    classifiers=[
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: Science/Research',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    include_package_data=True,
    install_requires=['future','uuid','moment']
)