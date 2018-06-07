"""
Copyright (c) 2018, Jairus Martin.

Distributed under the terms of the BSD License.

The full license is in the file LICENSE, distributed with this software.

Created on May, 2018
"""
import json
from atom.api import Atom, Str, Int, Range, Bool, List, Instance


class BInt(Range):
    def __init__(self):
        super(BInt, self).__init__(0, 1)


class Model(Atom):
    def to_json(self, *keys, **extra):

        def unpack(v):
            if isinstance(v, Model):
                return v.to_json()
            elif isinstance(v, list):
                return [unpack(it) for it in v]
            elif isinstance(v, tuple):
                return tuple([unpack(it) for it in v])
            elif isinstance(v, dict):
                return {k: unpack(v[k]) for k in v}
            return v
        if keys:
            state = {}
            for k in keys:
                v = getattr(self, k)
                state[k] = unpack(v)
        else:
            state = self.__getstate__()
        state.update(extra)
        return json.dumps(state)

    @classmethod
    def from_json(cls, **data):
        state = data.copy()
        for k, v in data.items():
            m = getattr(cls, k)
            #print(k, m)
            if isinstance(m, Instance):
                mcls = m.validate_mode[-1]
                if mcls is None:
                    raise ValueError("Can't reconstruct {}".format(k))
                #print("Converting", k, "to", mcls)
                state[k] = None if v is None else mcls.from_json(**v)
                #print("Converted!", k, "to", mcls)
            elif isinstance(m, List):
                # TODO: Recurse
                mcls = m.validate_mode[-1].validate_mode[-1]
                #print("List convertion", k, "to", mcls)
                if mcls is None:
                    raise ValueError("Can't reconstruct {}".format(k))
                state[k] = [mcls.from_json(**it) for it in v]

        return cls(**state)


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
    Value = Instance(str) # Can be none apparently
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




