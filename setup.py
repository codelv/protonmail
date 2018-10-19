"""
Copyright (c) 2018, Jairus Martin.

Distributed under the terms of the GPL License.

The full license is in the file LICENSE, distributed with this software.

Created on May, 2018
"""
from setuptools import setup, find_packages


setup(
    name='protonmail',
    version='0.1.3',
    author='frmdstryr',
    author_email='frmdstryr@gmail.com',
    url='https://gitlab.com/codelv/protonmail',
    description='An unofficial python client for protonmail',
    license="GPL",
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    install_requires=['pgpy', 'bcrypt', 'atom'],
    # also needs either ['treq'], or ['tornado'] or ['aiohttp']
    packages=find_packages(),
)
