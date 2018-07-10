"""
Copyright (c) 2018, Jairus Martin.

Distributed under the terms of the BSD License.

The full license is in the file LICENSE, distributed with this software.

Created on May, 2018
"""
import os

import protonmail

backend = protonmail.BACKEND.lower()

if backend == 'tornado':
    from .tw import *
elif backend == 'aiohttp':
    from .aio import *
elif backend == 'twisted':
    from .tx import *
else:
    raise EnvironmentError("Unknown backend: {}".format(backend))
