"""
Copyright (c) 2018, Jairus Martin.

Distributed under the terms of the GPL License.

The full license is in the file LICENSE, distributed with this software.

Created on May, 2018
"""
import sys

IS_PY3 = sys.version_info.major > 2


def str(s):
    """ Convert whatever s is to a string """
    return s.decode() if IS_PY3 and isinstance(s, bytes) else s


def join(s, items):
    """ Join without giving a %&#S what "type" s and items is """
    if IS_PY3:
        return str(s).join(map(str, items))
    return s.join(items)

