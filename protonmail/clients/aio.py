"""
Copyright (c) 2018, Jairus Martin.

Distributed under the terms of the BSD License.

The full license is in the file LICENSE, distributed with this software.

Created on May, 2018
"""
import types
import logging
import asyncio
import aiohttp
import aiohttp.client

from functools import wraps
from atom.api import Atom, Instance
from pprint import pformat
log = logging.getLogger('protonmail')

from http.cookiejar import CookieJar

class CoroutineExit(Exception):
    def __init__(self, value):
        self.value = value
        

def coroutine(f):
    """ Supports the "old" syntax. Based on twisted's impl. """
    @wraps(f)
    def unwind(*args, **kwargs):
        gen = f(*args, **kwargs)
        if not isinstance(gen, types.GeneratorType):
            raise TypeError(
                "coroutine requires %r to produce a generator; "
                "instead got %r" % (f, gen))
        return _unwrap(None, gen, asyncio.Future())
    return unwind


def _unwrap(result, g, future):
    while True:
        try:
            # Send the last result back as the result of the yield expression.
            if isinstance(result, Exception):
                result = g.throw(result)
            else:
                result = g.send(result)
        except (CoroutineExit, StopIteration) as e:
            # fell off the end, or "return" statement
            future.set_result(getattr(e, "value", None))
            return future
        except Exception as e:
            future.set_exception(e)
            return future
        if asyncio.iscoroutine(result):
            result = asyncio.ensure_future(result)
        if isinstance(result, asyncio.Future):
            result.add_done_callback(
                lambda r, g=g, f=future:_unwrap(
                    r.exception() or r.result(), g, f))
            return future
    return future


def return_value(value):
    raise CoroutineExit(value)


def run_sync(self, f, *args, **kwargs):
    timeout = kwargs.pop('timeout')
    
    @wraps(f)
    def wrapped():
        return f(*args, **kwargs)
    
    loop = asyncio.get_event_loop()
    loop.run_until_complete(wrapped)


class Response(Atom):
    """ Wraps the response 
    
    """
    response = Instance(aiohttp.client.ClientResponse)
    
    @property
    def code(self):
        return self.response.status
    
    def cookies(self):
        # Convert SimpleCookie to http.cookies
        return self.response.cookies
    
    def __getattr__(self, attr):
        return getattr(self.response, attr)
    

class Requests(Atom):
    """ Request wrapper """
    client = Instance(aiohttp.ClientSession, ())
    
    def __getattr__(self, attr):
        return lambda *args, **kwargs: self._request(attr, *args, **kwargs)
    
    @coroutine
    def _request(self, *args, **kwargs):
        client = self.client
        log.warning("Request: kwargs={}".format(pformat(kwargs)))
        r = yield client._request(*args, **kwargs)
        return_value(Response(response=r))
        

requests = Requests()
