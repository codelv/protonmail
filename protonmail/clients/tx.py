"""
Copyright (c) 2018, Jairus Martin.

Distributed under the terms of the GPL License.

The full license is in the file LICENSE, distributed with this software.

Created on May, 2018
"""
import treq
from functools import wraps
from twisted.internet.defer import inlineCallbacks, returnValue


#: Use directly
coroutine = inlineCallbacks

#: Use directly
return_value = returnValue

#: Use crochet to run sync
def run_sync(f, *args, **kwargs):
    import crochet
    timeout = kwargs.pop('timeout', None)
    
    @wraps(f)
    def wrapped():
        return f(*args, **kwargs)
    
    if not run_sync._is_setup:
        crochet.setup()
        run_sync._is_setup = True
        
    return crochet.run_in_reactor(wrapped)().wait(timeout)
run_sync._is_setup = False

#: Map directly
requests = treq
