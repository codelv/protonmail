"""
Copyright (c) 2018, Jairus Martin.

Distributed under the terms of the GPL License.

The full license is in the file LICENSE, distributed with this software.

Created on May, 2018
"""
import sys
from atom.api import Atom, Instance
from tornado.gen import coroutine
from tornado.gen import Return
from tornado.httpclient import HTTPRequest, HTTPError
from tornado.simple_httpclient import HTTPResponse, AsyncHTTPClient
from requests.cookies import cookiejar_from_dict

try:
    import ujson as json
except ImportError:
    import json
    

if sys.version_info.major > 2:
    from http.cookies import SimpleCookie
else:
    from Cookie import SimpleCookie


def return_value(value):
    raise Return(value)


def run_sync(f, *args, **kwargs):
    raise NotImplementedError


class Response(Atom):
    """ Requests like wrapper for tornado's AsyncHTTPClient's responses.
    
    """
    response = Instance((HTTPResponse, HTTPError))
    
    def __getattr__(self, attr):
        return getattr(self.response, attr)
    
    def cookies(self):
        cookies = cookiejar_from_dict({})
        for cookie in self.response.headers.get_list('Set-Cookie'):
            cookies.update(SimpleCookie(cookie))
        return cookies
    
    @coroutine
    def json(self):
        r = json.loads(self.response.body)
        return_value(r)
        
    
class Requests(Atom):
    """ Requests like wrapper for tornado's AsyncHTTPClient
    
    """
    
    client = Instance(AsyncHTTPClient, ())
    
    def __getattr__(self, attr):
        def request(**kwargs):
            kwargs['method'] = attr.upper()
            return self.request(**kwargs)
        return request
    
    @coroutine
    def request(self, **kwargs):
        client = self.client
        form = kwargs.pop('json', None)
        cookies = kwargs.pop('cookies', {})
        headers = kwargs.get('headers', {})
        if form:
            headers['Content-Type'] = 'application/json; charset=UTF-8'
            kwargs['body'] = json.dumps(
                form, separators=(u',', u':')).encode('utf-8')
        if cookies:
            headers['Cookie'] = ";".join(["=".join(c) for c in cookies.items()])
        kwargs['headers'] = headers
        request = HTTPRequest(**kwargs)
        try:
            r = yield client.fetch(request)
        except HTTPError as e:
            r = e.response or e
        return_value(Response(response=r))


requests = Requests()
