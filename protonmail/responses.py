"""
Copyright (c) 2018, Jairus Martin.

Distributed under the terms of the GPL License.

The full license is in the file LICENSE, distributed with this software.

Created on May, 2018
"""
from atom.api import Str, Bytes, Int, Dict, List, Instance
from protonmail.models import (
    Model, BInt, User, UserSettings, MailSettings, Message, Conversation,
    Contact, Notice, UnreadCount, Label, Location
)


class Response(Model):
    Code = Int()
    Error = Str()
    ErrorDescription = Str()

    def dump(self):
        return self.__getstate__()


class AuthInfoResponse(Response):
    """ Expected response from api/auth/info """
    
    Modulus = Bytes()
    ServerEphemeral = Bytes()
    Version = Int()
    Salt = Bytes()
    SRPSession = Str()
    TwoFactor = BInt()
    


class AuthResponse(Response):
    """ Expected response from api/auth """
    AccessToken = Str()
    ExpiresIn = Int()
    Scope = Str()
    Uid = Str()
    UID = Str()
    RefreshToken = Str()
    EventID = Str()
    ServerProof = Str()
    PasswordMode = Int()
    PrivateKey = Str()
    EncPrivateKey = Bytes()
    KeySalt = Bytes()
    TokenType = Str()


class AuthCookiesResponse(Response):
    """ Expected response from api/auth/cookies """
    SessionToken = Str()
    UID = Str()


class UsersResponse(Response):
    """ Expected response from api/users """
    User = Instance(User)


class SettingsResponse(Response):
    """ Expected response from api/settings """
    UserSettings = Instance(UserSettings)


class MailResponse(Response):
    """ Expected response from api/mail """
    MailSettings = Instance(MailSettings)


class MessageReadResult(Response):
    ID = Str()


class MessageReadResponse(Response):
    """ Expected response from put api/messages/read """
    Responses = List(MessageReadResult)


class MessageResponse(Response):
    """ Expected response from put api/messages/<id> """
    Message = Instance(Message)


class MessageSendResponse(Response):
    """ Expected response from put api/messages/send/<id> """
    Sent = Instance(Message)


class UsersPubKeyResponse(Response):
    """ Expected response from api/users/pubkey/<user> 
    Returns the code and the email of each user """
    Keys = Dict()

    @classmethod
    def from_json(cls, **data):
        return UsersPubKeyResponse(**data)

    def __init__(self, Code, **kwargs):
        super(UsersPubKeyResponse, self).__init__(Code=Code, Keys=kwargs)


class EventsResult(Model):
    Locations = List(Location)
    Labels = List(Label)
    Starred = Int()


class MessageEvent(Model):
    ID = Int()
    Action = Int()
    Message = Instance(Message)


class ConversationEvent(Model):
    Action = Int()
    Conversation = Instance(Conversation)


class EventsResponse(Response):
    """ Expected response from api/events/<id> """
    EventID = Str()
    Refresh = BInt()
    More = BInt()
    Notices = List(Notice)
    UsedSpace = Int()
    Messages = List(MessageEvent)
    MessageCounts = List(UnreadCount)
    ConversationCounts = List(UnreadCount)
    Conversations = List(ConversationEvent)
    Total = Instance(EventsResult)
    Unread = Instance(EventsResult)


class MessagesResponse(Response):
    """ Expected response from api/messages """
    Limit = Int()
    Total = Int()
    Messages = List(Message)


class ConversationsResponse(Response):
    """ Expected response from api/conversations """
    Limit = Int()
    Total = Int()
    Conversations = List(Conversation)


class ConversationResponse(Response):
    """ Expected response from api/conversations/<id> """
    Conversation = Instance(Conversation)
    Messages = List(Message)


class ContactsResponse(Response):
    """ Expected response from api/contacts """
    Limit = Int()
    Total = Int()
    Contacts = List(Contact)


class ContactResponse(Response):
    """ Expected response from api/contacts/<id> """
    Contact = Instance(Contact)

