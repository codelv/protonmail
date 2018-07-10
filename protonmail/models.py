"""
Copyright (c) 2018, Jairus Martin.

Distributed under the terms of the BSD License.

The full license is in the file LICENSE, distributed with this software.

Created on May, 2018
"""
import sys
from base64 import b64encode as b64e
from protonmail import auth, utils
from pgpy import PGPMessage
from atom.api import (
    Atom, Str, Int, Range, Bool, List, Dict, Instance, ForwardInstance
)
from atom.dict import _DictProxy

IS_PY3 = utils.IS_PY3


class BInt(Range):
    def __init__(self):
        super(BInt, self).__init__(0, 1)


class Model(Atom):
    #: Extra keys that don't fit
    _keys = Dict()

    def to_json(self, *keys, **extra):

        def unpack(v):
            if isinstance(v, Model):
                return v.to_json()
            elif isinstance(v, (tuple, list)):
                return [unpack(it) for it in v]
            elif isinstance(v, (dict, _DictProxy)):
                return {unpack(k): unpack(v[k]) for k in v}
            elif IS_PY3 and isinstance(v, bytes):
                return v.decode()
            return v
        if keys:
            state = {}
            for k in keys:
                state[k] = unpack(getattr(self, k))
        else:
            state = self.__getstate__()
            for k, v in state.items():
                state[k] = unpack(getattr(self, k))
        for k, v in extra.items():
            state[k] = unpack(v)
        return state

    @classmethod
    def from_json(cls, **data):
        state = data.copy()
        state['_keys'] = {}
        for k, v in data.items():
            m = getattr(cls, k, None)
            if m is None:
                state['_keys'][k] = state.pop(k)
                continue
            #print(k, m)re
            if isinstance(m, Instance):
                mcls = m.validate_mode[-1]
                if mcls is None:
                    raise ValueError("Can't reconstruct {}".format(k))
                #print("Converting", k, "to", mcls)
                if v is None:
                    state[k] = None
                    continue
                state[k] = (mcls.from_json(**v)
                            if issubclass(mcls, Model) else mcls(v))

                #print("Converted!", k, "to", mcls)
            elif isinstance(m, List):
                # TODO: Recurse
                mcls = m.validate_mode[-1].validate_mode[-1]
                #print("List convertion", k, "to", mcls)
                if mcls is None:
                    raise ValueError("Can't reconstruct {}".format(k))
                state[k] = [mcls.from_json(**it)
                            if issubclass(mcls, Model)
                            else mcls(it)
                            for it in v]

        return cls(**state)

    # def __repr__(self):
    #     r = super(Model, self).__repr__()
    #     state = self.__getstate__()
    #     return "{} {}>".format(r.split(" ")[0],
    #                            ",".join(["{}={}".format(k, v)
    #                                      for k, v in state.items()]))


class TwoFactorCode(Model):
    pass


class AutoResponder(Model):
    # Pretty sure someone screwed up here
    startTime = Int()
    endTime = Int()
    zone = Str()
    daysSelected = List(str)
    subject = Str()
    message = Str()
    isEnabled = Bool()
    repeat = BInt()

    StartTime = Int()
    EndTime = Int()
    Subject = Str()
    Message = Str()
    DaysSelected = List(str)
    IsEnabled = Bool()
    Repeat = BInt()
    Zone = Str()


class VPN(Model):
    ExpirationTime = Int()
    MaxConnect = Int()
    MaxTier = Int()
    PlanName = Str()
    Status = BInt()


class Activation(Model):
    pass


class Key(Model):
    ID = Str()
    Version = Int()
    PublicKey = Str()
    PrivateKey = Str()
    Fingerprint = Str()
    Activation = Instance(Activation)
    Primary = BInt()
    Flags = Int()


class Address(Model):
    ID = Str()
    DomainID = Str()
    Email = Str()
    Send = Int()
    Receive = Int()
    Status = Int()
    Type = Int()
    Order = Int()
    DisplayName = Str()
    Signature = Str()
    HasKeys = BInt()
    Keys = List(Key)


class Email(Model):
    Value = Str()
    Status = BInt()
    Notify = BInt()
    Reset = BInt()


class Phone(Model):
    Value = Instance(str)  # Can be none apparently
    Status = BInt()
    Notify = BInt()
    Reset = BInt()


class UserSettings(Model):
    PasswordMode = BInt()
    Email = Instance(Email)
    News = Int()
    Locale = Str()
    LogAuth = BInt()
    InvoiceText = Str()
    TwoFactor = BInt()
    Phone = Instance(Phone)


class MailSettings(Model):
    LastLoginTime = Int()
    DisplayName = Str()
    Signature = Str()
    Theme = Str()
    AutoResponder = Instance(AutoResponder)
    AutoSaveContacts = BInt()
    AutoWildcardSearch = BInt()
    Autocrypt = BInt()
    ComposerMode = Int()
    MessageButtons = BInt()
    ShowImages = BInt()
    ViewMode = Int()
    ViewLayout = Int()
    SwipeLeft = BInt()
    SwipeRight = BInt()
    AlsoArchive = BInt()
    Hotkeys = BInt()
    PMSignature = Int()
    ImageProxy = Int()
    TLS = BInt()
    RightToLeft = Int()
    AttachPublicKey = BInt()
    Sign = BInt()
    PGPScheme = Int()
    PromptPin = BInt()
    AutoCrypt = BInt()
    NumMessagePerPage = Int()
    DraftMIMEType = Str('text/html')
    ReceiveMIMEType = Str('text/html')
    ShowMIMEType = Str('text/html')


class User(UserSettings, MailSettings):
    ID = Str()
    Name = Str()
    UsedSpace = Int()
    Currency = Str()
    Credit = Int()
    NotificationEmail = Str()
    Notify = BInt()
    PasswordReset = BInt()
    Language = Str()
    Images = Int()
    Moved = Int()
    ShowEmbedded = BInt()
    MaxSpace = Int()
    MaxUpload = Int()
    Subscribed = BInt()
    Services = Int()
    Role = Int()
    Private = Int()
    VPN = Instance(VPN)
    Delinquent = BInt()
    Addresses = List(Address)
    Keys = List(Key)
    PublicKey = Str()
    EncPrivateKey = Str()
    U2FKeys = List(str)
    TOTP = Int()


class EmailAddress(Model):
    Address = Str()
    Name = Str()
    Group = Str()


# class ParsedHeaders(Model):
#     To = Str()
#     From = Str()
#     Date = Str()
#     Subject = Str()
class Attachment(Model):
    pass


class UnreadCount(Model):
    LabelID = Int()
    Total = Int()
    Unread = Int()


def _client():
    from protonmail.client import Client
    return Client


class Message(Model):
    SEND_PM = 1
    SEND_EO = 2
    SEND_CLEAR = 4
    SEND_PGP_INLINE = 8
    SEND_PGP_MIME = 16
    SEND_MIME = 32
    
    TYPE_DRAFT = 1

    ID = Str()
    Order = Int()
    Subject = Str()
    Body = Str()
    #: Decrypted body
    DecryptedBody = Str()
    AddressID = Str()
    Size = Int()
    
    Password = Str()
    PasswordHint = Str()

    ConversationID = Str()
    ExpirationTime = Int()
    Time = Int()
    ExternalID = Instance(str)
    HasAttachment = BInt()
    NumAttachments = Int()
    Attachments = List(Attachment)

    ToList = List(EmailAddress)
    BCCList = List(EmailAddress)
    CCList = List(EmailAddress)
    ReplyTo = Instance(EmailAddress)
    ReplyTos = List(EmailAddress)

    Sender = Instance(EmailAddress)
    SenderAddress = Str()
    SenderName = Str()

    Starred = BInt()
    SpamScore = Int()
    IsEncrypted = Int()
    IsForwarded = BInt()
    IsRead = BInt()
    IsReplied = BInt()
    IsRepliedAll = BInt()
    IsAutoReply = BInt()
    LabelIDs = List(str)
    Location = Int()
    Type = Int()
    Unread = Int()

    MIMEType = Str("text/html")
    Header = Str()
    ParsedHeaders = Dict()
    
    Client = ForwardInstance(_client)

    def encrypt(self, key):
        """ Encrypts the DecryptedBody for the given client's key and sets it 
        as the Body of this message.
        
        Parameters
        ----------
        key: pgpy.PGPKey
            An unlocked PGPKey
            
        Returns
        -------
        msg: String
            The encrypted message

        """
        m = key.encrypt(PGPMessage.new(self.DecryptedBody))
        self.Body = str(m)
        return self.Body

    def decrypt(self, key):
        """ Decrypts the Body and sets the DecryptedBody 
         of this message.
        
        Parameters
        ----------
        key: pgpy.PGPKey
            An unlocked PGPKey
            
        Returns
        -------
        msg: String
            The decrypted message

        """
        msg = PGPMessage.from_blob(self.Body)
        if msg.is_encrypted:
            self.DecryptedBody = key.decrypt(msg).message
        else:
            self.DecryptedBody = self.Body
        return self.DecryptedBody

    def is_encrypted(self):
        if not self.Body:
            return False
        return PGPMessage.from_blob(self.Body).is_encrypted

    def is_draft(self):
        return self.Type == 1

    def is_plaintext(self):
        return self.MIMEType == "text/plain"

    def generate_reply_token(self):
        return b64e(auth.generate_session_key())
    
    def send(self):
        if not self.Client:
            raise RuntimeError("No client set!")
        self.Client.send_message(self)
            
    def read(self):
        if self.Client:
            raise RuntimeError("No client set!")
        self.Client.read_message(self)
        
    def save(self):
        if self.Client:
            raise RuntimeError("No client set!")
        self.Client.save_draft(self)

    def to_json(self, *keys, **extra):
        """ Make sure the DecryptedBody never accidentally leaves. """
        state = super(Message, self).to_json(*keys, **extra)
        state.pop("DecryptedBody", "")
        return state


class Label(Model):
    ID = Str()
    ContextNumAttachments = Int()
    ContextNumMessages = Int()
    ContextNumUnread = Int()
    ContextSize = Int()
    ContextTime = Int()


class Conversation(Label):
    LabelIDs = List(str)
    Labels = List(Label)
    NumAttachments = Int()
    NumMessages = Int()
    NumUnread = Int()
    ExpirationTime = Int()
    Order = Int()
    Recipients = List(EmailAddress)
    Senders = List(EmailAddress)
    Size = Int()
    Subject = Str()
    Time = Int()


class ContactEmail(Model):
    ID = Str()
    Name = Str()
    Email = Str()
    Type = List(str)
    Defaults = Int()
    Order = Int()
    ContactID = Str()
    LabelIDs = List(str)


class Signature(Model):
    pass


class ContactCard(Model):
    Type = Int()
    Date = Str()
    Signature = Instance(Signature)


class Contact(Model):
    ID = Str()
    UID = Str()
    Name = Str()
    LabelIDs = List(str)
    CreateTime = Int()
    ModifyTime = Int()

    Size = Int()
    Cards = List(ContactCard)
    ContactEmails = List(ContactEmail)


class Notice(Model):
    pass


class Location(Model):
    Location = Int()
    Count = Int()
