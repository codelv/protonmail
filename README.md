# Protonmail

A protonmail client in python using treq, atom, bcrypt, and pgpy. 

It can be used sync or async thanks to crochet.


## Usage

Create a client for a given user and pass the password to the login method.

```python
from getpass import getpass
from protonmail.client import Client

# Login
client = Client(username="someuser", 
                blocking=True)  # It's async by default
client.api.login(getpass())


```

Once authenticated and unlocked, you can do API requests using the dot 
notation or by calling request with the path. 

```python

# Use dot notation 
client.api.conversations.count()

# Or use request and the path
client.api.request('api/conversations/count')

# Can also pass method, body, headers, and cookies
client.api.messages.read(method='PUT', body={'IDs':['msid1...==', '...']})

# Poll for updates
client.api.events()


```

Use the webclient to see what API's are available.

#### Reading conversations


```python
from protonmail responses import ConversationsResponse, ConversationResponse 
 
# First get the list of messages
r = client.api.conversations(response=ConversationsResponse)


# Open the first conversation
conversation = r.Conversations[0]
r = client.api.conversations(conversation.ID, response=ConversationResponse)

# Open and read the first message from the conversation
r = client.read_message(r.Messages[0].ID)

# Now decrypt and read the message
m = client.read_message(m)
print(m.DecryptedBody)


```

#### Checking messages

```python
# Poll to see if any events occurred
# this passes the clients EventID by default
c.api.events() 

```

#### Sending messages

```python

from protonmail.models import EmailAddress

# Create a draft
r = client.create_draft()
draft = r.Message
draft.Subject = "Hello from python!"
draft.DecryptedBody = "JS got you down huh?"
draft.ToList = [
    EmailAddress(Address="user@example.com", Name="User"), # Non PM will be cleartext
    EmailAddress(Address="user@protonmail.com"), # PM will be ency
]

# Save the draft if needed
r = client.save_draft(draft)

# Now send it
r = client.send_message(draft)
if r.Code != 1000:
    print(r.Error)

```

Once done be sure to logout. 

```python
# Logout
c.api.logout()
```


### Comments

This was written based on the web client. Please audit the code and report bugs.

Thank you!
