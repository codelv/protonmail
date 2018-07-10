"""
Copyright (c) 2018, Jairus Martin.

Distributed under the terms of the BSD License.

The full license is in the file LICENSE, distributed with this software.

Created on May, 2018
"""
import os


BACKEND = os.environ.get('PROTONMAIL_BACKEND', 'twisted')


def get_client(**kwargs):
    """ Create and return a Client for a given backend. Once the backend has 
    been imported set it cannot be changed.
    
    Parameters
    ----------
    username: String
        Client username
    backend: String
        The backend to use. One of twisted, tornado, or aiohttp. 
        Default: twisted
    
    Returns
    -------
    client: protonmail.client.Client
        A client instance.
        
    """
    set_backend(kwargs.pop('backend', BACKEND))
    from .client import Client
    return Client(**kwargs)


def set_backend(backend):
    """ Set the backend. This selects the event loop and http interface used. 
    
    Parameters
    ----------
    backend: String
        The backend to use. One of twisted, tornado, or aiohttp. 
        Default: twisted
        
    """
    global BACKEND
    BACKEND = backend
    
