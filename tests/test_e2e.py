import pytest
from protonmail.client import Client
from protonmail.models import Message, EmailAddress

SUBJECT = "Testing 123"
MESSAGE = "This is a test"
PM_EMAIL = "test@protonmail.com"
CT_EMAIL = "test@gmail.com"


@pytest.fixture
def clients():
    alice = Client(Username='pytest', blocking=True)
    bob = Client(Username='pytest2', blocking=True)
    alice.api.login("protonmail")
    #c2.api.login("protonmail")
    try:
        yield (alice, bob)
    finally:
        alice.api.logout()



def test_send_pm(clients):
    alice, bob = clients
    resp = alice.create_draft()
    assert resp.Code == 1000
    draft = resp.Message
    draft.Subject = SUBJECT
    draft.DecryptedBody = MESSAGE
    draft.ToList = [EmailAddress(Address=PM_EMAIL)]
    resp = alice.save_draft(draft)
    assert resp.Code == 1000
    saved = resp.Message
    alice.read_message(saved)
    assert saved.Subject == SUBJECT
    assert saved.DecryptedBody == MESSAGE
    assert saved.ToList[0].Address == PM_EMAIL
    resp = alice.send_message(saved)
    assert resp.Code == 1000
    
    # TODO: Verify from another acct
    #bob.api.messages()
    
    
def test_send_clear(clients):
    alice, bob = clients
    resp = alice.create_draft()
    assert resp.Code == 1000
    draft = resp.Message
    draft.Subject = SUBJECT
    draft.DecryptedBody = MESSAGE
    draft.ToList = [EmailAddress(Address=CT_EMAIL)]
    resp = alice.save_draft(draft)
    assert resp.Code == 1000
        
    # Will be cleartext... but are you silly? I'm still gonna send it
    saved = resp.Message
    assert saved.ToList[0].Address == CT_EMAIL
    resp = alice.send_message(saved)
    assert resp.Code == 1000


def test_send_multiple(clients):
    alice, bob = clients
    resp = alice.create_draft()
    assert resp.Code == 1000
    draft = resp.Message
    draft.Subject = SUBJECT
    draft.DecryptedBody = MESSAGE
    draft.ToList = [EmailAddress(Address=PM_EMAIL),
                    EmailAddress(Address=CT_EMAIL)]
    resp = alice.save_draft(draft)
    assert resp.Code == 1000
        
    saved = resp.Message
    resp = alice.send_message(saved)
    assert resp.Code == 1000
    
