"""
Copyright (c) 2018, Jairus Martin.

Distributed under the terms of the BSD License.

The full license is in the file LICENSE, distributed with this software.

Created on May, 2018
"""
import sys
import logging
from pprint import pformat
from atom.api import Str, Bytes, Int, Instance, ForwardInstance, List, Dict, Bool
from base64 import b64decode as b64d
from base64 import b64encode as b64e
from pgpy import PGPMessage, PGPKey
from pgpy.constants import SymmetricKeyAlgorithm
from protonmail.clients.api import coroutine, return_value, run_sync, requests
from protonmail.models import (
    Model, User, UserSettings, TwoFactorCode, Message, EmailAddress
)
from protonmail import auth, utils
from protonmail.responses import (
    Response, AuthInfoResponse, AuthCookiesResponse, AuthResponse,
    UsersPubKeyResponse, MessageResponse, UsersResponse, MessageSendResponse
)


if utils.IS_PY3:
    from http.cookiejar import CookieJar
    from http.cookies import SimpleCookie
else:
    from cookielib import CookieJar
    from Cookie import SimpleCookie
    

log = logging.getLogger('protonmail')
logging.basicConfig(level=logging.DEBUG)



class LoginError(Exception):
    pass


class LogoutError(Exception):
    pass


class AuthError(Exception):
    pass


class HttpError(Exception):
    pass


class SecurityError(Exception):
    pass


class Client(Model):
    """ Handles logging into protonmail
    
    """
    #: API access
    api = ForwardInstance(lambda: API)

    #: Use blocking API
    blocking = Bool()

    #: Debug api calls
    debug = Bool(True)
    
    #: Is logged in
    is_logged_in = Bool()
    

    def _default_api(self):
        return API(client=self)

    # =========================================================================
    # Parameters for api/auth/info
    # =========================================================================
    AppVersion = Str('Web_3.13.7')
    ApiVersion = Str('3')

    #: Username
    Username = Str()

    #: Web
    ClientID = Str("Web")

    #: Client secret from WebClient/env/configDefault.js
    ClientSecret = Str("4957cc9a2e0a2a49d02475c9d013478d")

    #: Auth info from login
    AuthInfo = Instance(AuthInfoResponse)

    # =========================================================================
    # Parameters for api/auth/
    # =========================================================================
    #: Computed client ephemeral, set in _default_ClientProof
    ClientEphemeral = Bytes()

    #: Default key size
    KeySize = Int(2048)

    #: Get the hashed password
    HashedPassword = Bytes()

    def _observe_HashedPassword(self, change):
        # Recalculate the proof when the HashedPassword changes
        self.ClientProof = self._default_ClientProof()

    def _default_ClientProof(self):
        """ Computes the ClientProof from the AuthInfo """
        info = self.AuthInfo
        proofs = auth.generate_proofs(
            self.KeySize,
            b64d(auth.read_armored(info.Modulus)),
            self.HashedPassword,
            b64d(info.ServerEphemeral)
        )

        self.ClientEphemeral = proofs['client_ephemeral']
        self.ExpectedServerProof = proofs['server_proof']

        return proofs['client_proof']

    #: Client proof
    ClientProof = Bytes()

    #: Expected server proof
    ExpectedServerProof = Bytes()

    #: Auth response from login
    Auth = Instance(AuthResponse)

    #: Code for api/auth
    TwoFactorCode = Instance(TwoFactorCode)

    EventID = Str()

    def _default_EventID(self):
        return self.Auth and self.Auth.EventID

    # =========================================================================
    # Parameters for api/auth/cookies/
    # =========================================================================

    #: Used for api/auth/cookies/
    ResponseType = Str("token")

    GrantType = Str("refresh_token")

    RedirectURI = Str("https://protonmail.com")

    def _default_State(self):
        return auth.generate_random_string(24)

    #: Random string
    State = Str()

    #: Result from the cookies request
    AuthCookies = Instance(AuthCookiesResponse)

    #: Cookies set
    Cookies = Instance((CookieJar, SimpleCookie))

    #: TODO: How to make this secure?
    SessionStorage = Dict()

    #: The hashed mailbox password
    MailboxPassword = Str()

    # =========================================================================
    # Results from api/users/
    # =========================================================================
    #: User info
    User = Instance(User)

    # =========================================================================
    # Results for api/settings/
    # =========================================================================
    #: Settings
    Settings = Instance(UserSettings)

    # =========================================================================
    # Results for api/settings/
    # =========================================================================
    #: Settings
    mail = Instance(UserSettings)

    #: Remote public keys
    PublicKeys = Dict()
    
    #: Encrypted private key
    PrivateKey = Instance(PGPKey)

    def _default_PrivateKey(self):
        if not self.Auth:
            return
        key, _ = PGPKey.from_blob(self.Auth.EncPrivateKey)
        return key

    def _observe_Auth(self, change):
        if self.Auth:
            self.PrivateKey = self._default_PrivateKey()
            self.is_logged_in = True
        else:
            del self.PrivateKey
            self.is_logged_in = False

    def get_public_keys(self, emails, timeout=None):
        """ Get the public keys for the given list of emails
        
        Parameters
        ----------
        emails: List or String
            Emails to retrieve
        timeout: Int or Float
            Time to wait when blocking
            
        Returns
        --------
        result: Dict
        """
        if not self.blocking:
            return self._get_public_keys(emails)
        return run_sync(self._get_public_keys, emails, timeout=timeout)

    @coroutine
    def _get_public_keys(self, emails):
        if isinstance(emails, (tuple, list)):
            emails = utils.join(",", emails)
        else:
            emails = utils.str(emails)
        if utils.IS_PY3:
            emails = emails.encode()
        r = yield self.api.users.pubkeys(b64e(emails),
                                         blocking=False,
                                         response=UsersPubKeyResponse)

        self.PublicKeys.update({u: PGPKey.from_blob(k)[0] if k else ''
                                for u, k in r.Keys.items()})
        return_value(r)

    def get_user_info(self, timeout=None):
        """ Get the info aboute this User
        
        Parameters
        ----------
        timeout: Int or Float
            Time to wait when blocking
            
        Returns
        --------
        result: User
        """
        if not self.blocking:
            return self._get_user_info()
        return run_sync(self._get_user_info, timeout=timeout)

    @coroutine
    def _get_user_info(self):
        r = yield self.api.users(blocking=False, response=UsersResponse)
        if r.Code == 1000:
            self.User = r.User
        return_value(r)

    def read_message(self, message, timeout=None):
        """ Read and decrypt a Message if necessary
       
        Parameters
        ----------
        message: protonmail.message.Message or Dict
   
        Returns
        -------
        result: String
            Decrypted message
        """
        if not self.blocking:
            return self._read_message(message)
        return run_sync(self._read_message, message, timeout=timeout)

    @coroutine
    def _read_message(self, message):
        if not isinstance(message, Message):
            raise TypeError("expected a protonmail.models.Message instance")

        # If the message hasn't been read yet, do that now
        if not message.Body:
            resp = yield self.api.messages(message.ID,
                                           blocking=False,
                                           response=MessageResponse)
            if resp.Code != 1000:
                raise ValueError("Unexpected response: {}".format(
                                 resp.to_json()))
            message = resp.Message

        # Read and decrypt if needed
        msg = PGPMessage.from_blob(message.Body)
        if msg.is_signed:
            email = message.SenderAddress
            if email not in self.PublicKeys:
                yield self._get_public_keys([email])
            pk = self.PublicKeys.get(email)
            if not pk:
                raise SecurityError("Failed to verify signed message!")
            pk.verify(msg)

        # Decrypt
        with self.PrivateKey.unlock(self.MailboxPassword) as key:
            message.decrypt(key)
        return_value(message)

    def create_draft(self, timeout=None):
        """ Create a message as a draft. This will populate an ID for 
        the message.
 
        Parameters
        ----------
        timeout: Int or Float
            Timeout to wait when blocking
         
        Returns
        -------
        result: protonmail.responses.MessageResponse
        """
        if not self.blocking:
            return self._create_draft()
        return run_sync(self._create_draft, timeout=timeout)

    @coroutine
    def _create_draft(self):
        user = self.User
        if not user:
            r = yield self._get_user_info()
            user = r.User
        address = user.Addresses[0]
        message = Message(
            AddressID=address.ID,
            IsRead=1,
            MIMEType='text/html',
            Sender=EmailAddress(Name=address.DisplayName,
                                Address=address.Email)
        )
        message.encrypt(self.PrivateKey.pubkey)

        r = yield self.api.messages.draft(
            method='POST', blocking=False, response=MessageResponse,
            json={
                'AttachmentKeyPackets': [],
                'id': None,
                'Message': message.to_json(
                    'AddressID', 'Sender', 'IsRead', 'CCList', 'BCCList',
                    'MIMEType', 'Subject', 'Body', 'ToList',
            )
        })
        if r.Message:
            r.Message.Client = self
        return_value(r)

    def save_draft(self, message, timeout=None):
        """ Encrypt (if necessary) and save the message as a draft.

        Parameters
        ----------
        message: protonmail.models.Message
        
        Returns
        -------
        result: protonmail.responses.MessageResponse
        """
        if not self.blocking:
            return self._save_draft(message)
        return run_sync(self._save_draft, message, timeout=timeout)

    @coroutine
    def _save_draft(self, message):
        if not isinstance(message, Message):
            raise TypeError("expected a protonmail.models.Message instance")
        if not message.ID:
            raise ValueError("Cannot save a draft without an ID. "
                             "Use create_draft first.")

        # Encrypt for this client only
        message.encrypt(self.PrivateKey.pubkey)

        # Should never happen
        if not message.is_encrypted():
            raise SecurityError("Failed to encrypted draft")

        r = yield self.api.messages.draft(
            message.ID, method='PUT', blocking=False, response=MessageResponse,
            json={
                'AttachmentKeyPackets': {},
                'id': message.ID,
                'Message': message.to_json('AddressID', 'Sender', 'IsRead',
                    'CCList', 'BCCList', 'MIMEType', 'Subject', 'Body',
                    'ToList',
                )
        })
        if r.Message:
            r.Message.Client = self
        return_value(r)

    def send_message(self, message, timeout=None):
        """ Encrypt and send the message.
        
        Parameters
        ----------
        message: protonmail.models.Message
        
        Returns
        -------
        result: protonmail.responses.MessageResponse
        """
        if not self.blocking:
            return self._send_message(message)
        return run_sync(self._send_message, message, timeout=timeout)

    @coroutine
    def _send_message(self, message):
        if not isinstance(message, Message):
            raise TypeError("expected a protonmail.models.Message instance")
        if not message.ToList:
            raise ValueError("message missing email to addresses")
        
        # Read draft from server if needed
        if message.ID and not message.Body:
            r = yield self.api.messages(message.ID, blocking=False,
                                        response=MessageResponse())
            message = r.Message
        
        # Decrypt
        if message.Body and not message.DecryptedBody:
            yield self._read_message(message)
            
        # Get any missing keys
        keys = self.PublicKeys
        emails = list(set([to.Address for to in (
                           message.ToList + message.CCList + message.BCCList)]))
        keys_needed = [e for e in emails if e not in keys]
        if keys_needed:
            yield self._get_public_keys(keys_needed)
            keys = self.PublicKeys
        
        # Extract the session key
        #cipher = SymmetricKeyAlgorithm.AES256
        #session_key = auth.generate_session_key(cipher)
        with self.PrivateKey.unlock(self.MailboxPassword) as uk:
            cipher, session_key = auth.decrypt_session_key(message.Body,
                                                           key=uk)
        
        pkg = {
            'Addresses': {},
            'Body': "",
            'MIMEType': message.MIMEType or "text/html",
            'Type': 0,
        }
        
        # If we need to send the key in clear
        cleartext = False
        for to in message.ToList:
            pk = keys.get(to.Address)
            if pk is None:
                raise SecurityError("Failed to get public key for: "
                                    "{}".format(to.Address))
            
            if pk:
                # Inside user
                # I guess the server does this? Encrypt body for email's pubkey 
                #pkg['Body'] = pk.encrypt(pkg['Body'], cipher=cipher,
                #                         sessionkey=session_key)
                
                # Encrypt the session key for this user
                sk = auth.encrypt_session_key(session_key, key=pk,
                                              cipher=cipher)
                
                pkg['Addresses'][to.Address] = {
                    'AttachmentKeyPackets': {},
                    'BodyKeyPacket': utils.str(b64e(sk)),
                    'Signature': 0,
                    'Type': Message.SEND_PM
                }
                pkg['Type'] |= Message.SEND_PM
            elif False and message.IsEncrypted:  # Disabled for now
                # Enc outside user
                token = message.generate_reply_token(cipher)
                enc_token = PGPMessage.new(
                    b64d(token)).encrypt(message.Password).message.__bytes__()
                
                pkg['Addresses'][to.Address] = {
                    'Auth': 0,
                    'PasswordHint': message.PasswordHint,
                    'Type': Message.SEND_EO,
                    'Token': token,
                    'EncToken': utils.str(b64e(enc_token)),
                    'AttachmentKeyPackets': {},
                    'BodyKeyPacket': utils.str(b64e(session_key)),
                    'Signature': int(pkg['Body'].is_signed),
                }
            else:
                cleartext = True
                
                # Outside user
                pkg['Addresses'][to.Address] = {
                    'Signature': 0,
                    'Type': Message.SEND_CLEAR
                }
                pkg['Type'] |= Message.SEND_CLEAR
                
        if cleartext and message.ExpirationTime and not message.Password:
            raise SecurityError("Expiring emails to non-ProtonMail recipients" \
                                "require a message password to be set")
        
        # Sending to a non PM user screws all security
        if cleartext:
            pkg['BodyKey'] = utils.str(b64e(session_key))
            pkg['AttachmentKeys'] = {}  # TODO
        
        # Get the message
        msg = PGPMessage.new(message.DecryptedBody)
        
        # Sign it
        with self.PrivateKey.unlock(self.MailboxPassword) as uk:
            msg |= uk.sign(msg)
        
        # Encrypt it using the session key and encode it
        msg = self.PrivateKey.pubkey.encrypt(msg, cipher=cipher,
                                             sessionkey=session_key)
        # Now encode it
        pkg['Body'] = utils.str(b64e(msg.message.__bytes__()))
    
        r = yield self.api.messages.send(
            message.ID, method='POST', blocking=False,
            response=MessageSendResponse,
            json={
                'ExpirationTime': 0,
                'id': message.ID,
                'Packages': [pkg]
            }

        )
        return_value(r)

    def check_events(self, timeout=None):
        """ Check for updates"""
        if not self.blocking:
            return self._check_events()
        return run_sync(self._check_events, timeout=timeout)

    @coroutine
    def _check_events(self):
        eid = id or self.EventID
        data = yield self.api.events(eid, blocking=False)
        self.EventID = data['EventID']
        return_value(data)
        
    def send_simple(self, **kwargs):
        """ Simple API for sending email """
        if not self.blocking:
            return self._send_simple(**kwargs)
        return run_sync(self._send_simple, **kwargs)
    
    @coroutine
    def _send_simple(self, to, subject="", body="", cc=None, bcc=None):
        if not to:
            raise ValueError("Please enter one or more recipient email "
                             "addresses")
        r = yield self._create_draft()
        if r.Code != 1000:
            raise ValueError("Failed to create draft: {}".format(r.to_json()))
        m = r.Message
        m.Subject = subject
        m.DecryptedBody = body
        if not isinstance(to, (tuple, list)):
            to = [to]
        m.ToList = [EmailAddress(Address=addr) for addr in to]
        if cc is not None:
            m.CCList = [EmailAddress(Address=addr) for addr in cc]
        if bcc is not None:
            m.BCCList = [EmailAddress(Address=addr) for addr in bcc]
        r = yield self._save_draft(m)
        if r.Code != 1000:
            raise ValueError("Failed to save draft: {}".format(r.to_json()))
        r = yield self._send_message(m)
        if r.Code != 1000:
            raise ValueError("Failed to send message: {}".format(r.to_json()))
        return_value(r)
       

class API(Model):
    """ Wrapper for the get API """
    #: Client info this API uses
    client = Instance(Client)

    #: Default headers
    headers = Dict()

    #: Host for requests
    host = Str("https://mail.protonmail.com/")

    #: Path for using dot notation
    path = List(str, default=['api'])

    def _default_headers(self):
        client = self.client
        return {
            'Accept': '*/*',
            'Connection': 'keep-alive',
            'Host': 'mail.protonmail.com',
            'Origin': self.host,
            'Referer': self.host,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                          'AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/66.0.3359.139 Safari/537.36',
            'x-pm-apiversion': client.ApiVersion,
            'x-pm-appversion': client.AppVersion
        }

    def login(self, password, unlock=True, timeout=None):
        """ Login and unlock Protonmail """
        if not self.client.blocking:
            return self._login(password, unlock)
        return run_sync(self._login, password, unlock, timeout=timeout)

    @coroutine
    def _login(self, password, unlock=True):
        client = self.client
        host = self.host
        headers = self.headers.copy()
        headers.update({
            'Accept': 'application/vnd.protonmail.v1+json',
            'Referer': host+"login",
        })

        # Get the auth info
        r = yield requests.post(
            url=host+"api/auth/info",
            json=client.to_json('Username', 'ClientID', 'ClientSecret'),
            headers=headers
        )

        if r.code != 200:
            raise LoginError("Unexpected info response: {}".format(r.code))
        data = yield r.json()

        # Parses the response and computes the proof
        resp = client.AuthInfo = AuthInfoResponse.from_json(**data)
        if resp.Code != 1000:
            raise LoginError("Unexpected info code: {}".format(resp.Code))
        if resp.TwoFactor:
            raise NotImplementedError("Two factor auth is not implemented")

        # Compute the hashed password
        client.HashedPassword = auth.hash_password(
            int(client.ApiVersion), password, b64d(resp.Salt), client.Username,
            b64d(auth.read_armored(resp.Modulus)))

        # Update headers
        headers.update({
            'Accept': '*/*',
        })

        # Authenticate
        r = yield requests.post(
            url=host+"api/auth",
            json=client.to_json(
                'Username', 'ClientID', 'ClientSecret', 'TwoFactorCode',
                SRPSession=client.AuthInfo.SRPSession,
                ClientProof=b64e(client.ClientProof),
                ClientEphemeral=b64e(client.ClientEphemeral)
            ),
            headers=headers
        )
        if r.code != 200:
            raise LoginError("Unexpected auth response: {}".format(r.code))

        data = yield r.json()

        resp = client.Auth = AuthResponse.from_json(**data)
        if resp.Code != 1000:
            del client.Auth
            raise LoginError("Unexpected auth code: {}".format(resp.Code))
        if b64d(resp.ServerProof) != client.ExpectedServerProof:
            del client.Auth
            raise AuthError("Invalid server authentication")

        # Login success
        if not unlock:
            return_value(resp)

        # And unlock
        unlocked = yield self._unlock(password)
        return_value((resp, unlocked))

    def unlock(self, password, timeout=None):
        """ Unlock to Protonmail """
        if not self.client.blocking:
            return self._unlock(password)
        return run_sync(self._unlock, password, timeout=timeout)

    @coroutine
    def _unlock(self, password):
        client = self.client
        host = self.host
        headers = self.headers.copy()

        # Compute access key
        pwd = auth.compute_key_password(password,
                                        b64d(client.Auth.KeySalt))

        # Decode the access token
        token = auth.check_mailbox_password(client.Auth.EncPrivateKey,
                                            pwd, client.Auth.AccessToken)
        
        # Stupid python 3
        authorization = 'Bearer ' + utils.str(token)
        
        headers.update({
            'Accept': '*/*',
            'Authorization': authorization,
            'Referer': host + "login/unlock",
            'x-pm-uid': client.Auth.Uid
        })

        # Get the cookies
        r = yield requests.post(
            url=host + "api/auth/cookies",
            json=client.to_json(
                'ResponseType', 'ClientID', 'GrantType', 'RedirectURI',
                'State', Uid=client.Auth.Uid,
                RefreshToken=client.Auth.RefreshToken
            ),
            headers=headers
        )

        if r.code != 200:
            raise LoginError("Unexpected unlock response: "
                             "{}".format(r.code))

        data = yield r.json()

        # Save the hashed mailbox password
        client.MailboxPassword = pwd

        result = client.AuthCookies = AuthCookiesResponse.from_json(**data)
        if result.Code == 1000:
            client.Cookies = r.cookies()
        return_value(result)

    def logout(self, timeout=None):
        """ Logout of Protonmail """
        if not self.client.blocking:
            return self._logout()
        return run_sync(self._logout, timeout=timeout)

    @coroutine
    def _logout(self):
        client = self.client
        data = yield self.request("api/auth", method='DELETE', blocking=False)
        result = Response.from_json(**data)
        if result.Code != 1000:
            raise LoginError("Unexpected logout code: {}".format(result.Code))
        del client.AuthInfo
        del client.Auth
        del client.AuthCookies
        del client.MailboxPassword
        return_value(result)

    def request(self, path, body=None, method='GET', cookies=None,
                headers=None, response=None, timeout=None, blocking=None,
                **kwargs):
        """ Perform the request automatically sending the authentication
        cookies and expected headers.
        
        Parameters
        ----------
        path: String
            The path to request
        body: String, List, or Dict
            The body of the request
        method: String
            Request method
        cookies: CookieJar
            Request cookies
        headers: Dict
            Request headers
        response: protonmail.responses.Response
            Expected response to parse from the request
        blocking: Bool
            Override default blocking
        timeout: Number
            Timeout to use when blocking
        kwargs: Object
            Extra kwarts to pass to treq (ex json)
        """
        blocking = blocking if blocking is not None else self.client.blocking

        def request():
            return self._request(path, body, method, cookies, headers,
                                 response, **kwargs)
        if blocking:
            return run_sync(request, timeout=timeout)
        return request()

    @coroutine
    def _request(self, path, body=None, method='GET', cookies=None,
                 headers=None, response=None, **kwargs):
        client = self.client

        if not client.Auth:
            raise LoginError("Must login first!")
        if not client.AuthCookies:
            raise AuthError("Must unlock the keys first!")
        if response is not None and not issubclass(response, Response):
            raise ValueError("response must be a subclass Response. "
                             "Got {}".format(response))
        h = self.headers.copy()
        h.update({'x-pm-uid': client.Auth.Uid})

        url = self.host+path.lstrip("/")
        if client.debug:
            log.warning("Request: method={}, url={}, body={}, cookies={}, "
                        "headers={} kwargs={}".format(
                            method, url, body, cookies, headers, 
                            pformat(kwargs)))
        r = yield requests.request(method=method,
                                   url=url,
                                   body=body,
                                   cookies=cookies or client.Cookies,
                                   headers=headers or h,
                                   **kwargs)
        if r.code != 200:
            log.warning("Unexpected HTTP response: {}".format(r.code))
        data = yield r.json()
        if client.debug:
            log.warning("Response: {} - {}".format(r, pformat(data)))
        if response is not None:
            return_value(response.from_json(**data))
        return_value(data)

    def __getattr__(self, item):
        """ Return an alias so you can do requests using the dot notation.
         
        """
        return API(client=self.client, path=self.path+[item])

    def __call__(self, path="", **kwargs):
        """ Invoke request when using the dot notation. 
        
        Examples
        --------
        # Same as client.request('api/messages/count')
        - client.api.messages.count()
        
        # Same as client.request('api/conversations/convo-id-string...==')
        - client.api.conversations('convo-id-string...==')
        
        """
        parts = (self.path + [path]) if path else self.path
        url = utils.join("/", parts)
        return self.request(url, **kwargs)

    def __repr__(self):
        cls = self.__class__
        name = cls.__module__+cls.__name__
        return "<{} {}>".format(name, '/'.join(self.path))
