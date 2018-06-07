# Protonmail

A protonmail client in python using twisted's treq


## Usage

```python
from getpass import getpass
from protonmail.client import Client

# Login
c = Client(username="someuser", blocking=True) 
c.api.login(getpass())

# Use dot notation 
c.api.conversations.count()

# Or use request and the path
c.api.request('api/conversations/count')

# Can also pass method, body, headers, and cookies
c.api.messages.read(method='PUT', body={'IDs':['msid1', '...']})

# Poll for updates
c.api.events()

# Logout
c.api.logout()


```