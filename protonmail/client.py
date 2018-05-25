"""

"""
import pgpy
import treq
import crochet
from pprint import pprint
from cookielib import CookieJar
from twisted.web import http
from twisted.internet.defer import inlineCallbacks
from atom.api import Str, Int, Instance, ForwardInstance, List, Dict, Bool
from base64 import b64decode as b64d
from base64 import b64encode as b64e

from protonmail.models import Model, BInt, User, UserSettings, MailSettings
from protonmail import auth


class LoginError(Exception):
    pass


class LogoutError(Exception):
    pass


class AuthError(Exception):
    pass


class Response(Model):
    Code = Int()


class AuthInfoResponse(Response):
    """ Expected response from api/auth/info """
    Modulus = Str()
    ServerEphemeral = Str()
    Version = Int()
    Salt = Str()
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
    EncPrivateKey = Str()
    KeySalt = Str()
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


class TwoFactorCode(Model):
    pass


class Client(Model):
    """ Handles logging into protonmail
    
    """
    #: API access
    api = ForwardInstance(lambda: API)

    #: Use blocking API
    blocking = Bool()

    def _default_api(self):
        return API(client=self, blocking=self.blocking)

    # =========================================================================
    # Parameters for api/auth/info
    # =========================================================================
    AppVersion = Str('Web_3.13.7')
    ApiVersion = Int(3)

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
    ClientEphemeral = Str()

    #: Default key size
    KeySize = Int(2048)

    #: Get the hashed password
    HashedPassword = Str()

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
    ClientProof = Str()

    #: Expected server proof
    ExpectedServerProof = Str()

    #: Auth response from login
    Auth = Instance(AuthResponse)

    #: Code for api/auth
    TwoFactorCode = Instance(TwoFactorCode)

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
    Cookies = Instance(CookieJar)

    #: TODO: How to make this secure?
    SessionStorage = Dict()

    # =========================================================================
    # Results from api/users/
    # =========================================================================
    #: Users returned
    users = List(User)

    # =========================================================================
    # Results for api/settings/
    # =========================================================================
    #: Settings
    settings = Instance(UserSettings)

    def read_pgp_message(self, message):
        """ Read a PGP Message
        
        Parameters
        ----------
        message: String
    
        Returns
        -------
        result: PGPMessage
        """
        return pgpy.PGPMessage.from_blob(message)

    def read_pgp_key(self, message, key):
        """ Read an encrypted PGP key
        
        Parameters
        ----------
        message: String
        key: String or Bytes
    
        Returns
        -------
        result: PGPKey
        """
        pgp_key = pgpy.PGPKey.from_blob(key)
        pgp_key.unlock(key)


class API(Model):
    """ Wrapper for the get API """
    #: Client info this API uses
    client = Instance(Client)

    #: Default headers
    headers = Dict()

    #: Async or sync
    blocking = Bool()

    def _default_headers(self):
        client = self.client
        return {
            'Accept': '*/*',
            'Connection': 'keep-alive',
            'Content-Type': "application/json;charset=utf-8",
            'Host': 'mail.protonmail.com',
            'Origin': 'https://mail.protonmail.com',
            'Referer': "https://mail.protonmail.com/",
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                          'AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/66.0.3359.139 Safari/537.36',
            'x-pm-apiversion': str(client.ApiVersion),
            'x-pm-appversion': client.AppVersion
        }

    def login(self, password, timeout=None):
        if not self.blocking:
            return self._login(password)
        crochet.setup()
        return crochet.run_in_reactor(
            lambda: self._login(password))().wait(timeout)

    @inlineCallbacks
    def _login(self, password):
        client = self.client
        headers = self.headers.copy()
        headers.update({
            'Accept': 'application/vnd.protonmail.v1+json',
            'Referer': "https://mail.protonmail.com/login",
        })

        # Get the auth info
        r = yield treq.post(
            "https://mail.protonmail.com/api/auth/info",
            client.to_json('Username', 'ClientID', 'ClientSecret'),
            headers=headers
        )

        if r.code != http.OK:
            raise LoginError("Unexpected info response: {}".format(r.code))
        data = yield r.json()
        pprint(data)

        # Parses the response and computes the proof
        resp = client.AuthInfo = AuthInfoResponse.from_json(**data)
        if resp.Code != 1000:
            raise LoginError("Unexpected info code: {}".format(resp.Code))
        if resp.TwoFactor:
            raise NotImplementedError("Two factor auth is not implemented")

        # Compute the hashed password
        client.HashedPassword = auth.hash_password(
            client.ApiVersion, password, b64d(resp.Salt), client.Username,
            b64d(auth.read_armored(resp.Modulus)))

        # Update headers
        headers.update({
            'Accept': '*/*',
        })

        # Authenticate
        r = yield treq.post(
            "https://mail.protonmail.com/api/auth",
            client.to_json(
                'Username', 'ClientID', 'ClientSecret', 'TwoFactorCode',
                SRPSession=client.AuthInfo.SRPSession,
                ClientProof=b64e(client.ClientProof),
                ClientEphemeral=b64e(client.ClientEphemeral)
            ),
            headers=headers
        )
        if r.code != http.OK:
            raise LoginError("Unexpected auth response: {}".format(r.code))

        data = yield r.json()
        pprint(data)

        resp = client.Auth = AuthResponse.from_json(**data)
        if resp.Code != 1000:
            raise LoginError("Unexpected auth code: {}".format(resp.Code))
        if b64d(resp.ServerProof) != client.ExpectedServerProof:
            raise AuthError("Invalid server authentication")

    def unlock(self, password, timeout=None):
        if not self.blocking:
            return self._unlock(password)
        return crochet.run_in_reactor(
            lambda: self._unlock(password))().wait(timeout)

    @inlineCallbacks
    def _unlock(self, password):
        client = self.client
        headers = self.headers.copy()

        # Compute access key
        pwd = auth.compute_key_password(password,
                                        b64d(client.Auth.KeySalt))
        # Decode the access token
        token = auth.check_mailbox_password(client.Auth.EncPrivateKey,
                                            pwd, client.Auth.AccessToken)

        headers.update({
            'Accept': '*/*',
            'Authorization': 'Bearer ' + token,
            'Referer': "https://mail.protonmail.com/login/unlock",
            'x-pm-uid': client.Auth.Uid
        })

        # Get the cookies
        r = yield treq.post(
            "https://mail.protonmail.com/api/auth/cookies",
            client.to_json(
                'ResponseType', 'ClientID', 'GrantType', 'RedirectURI',
                'State', Uid=client.Auth.Uid,
                RefreshToken=client.Auth.RefreshToken
            ),
            headers=headers
        )

        if r.code != http.OK:
            raise LoginError("Unexpected unlock response: "
                             "{}".format(r.code))

        data = yield r.json()
        pprint(data)

        result = client.AuthCookies = AuthCookiesResponse.from_json(**data)
        if result.Code == 1000:
            client.Cookies = r.cookies()

    def logout(self, timeout=None):
        if not self.blocking:
            return self._logout()
        return crochet.run_in_reactor(self._logout)().wait(timeout)

    @inlineCallbacks
    def _logout(self):
        client = self.client
        headers = self.headers.copy()
        headers.update({
            'x-pm-uid': client.Auth.Uid
        })
        # Get the cookies
        r = yield treq.delete(
            "https://mail.protonmail.com/api/auth",
            headers=headers,
            cookies=client.Cookies
        )

        if r.code != http.OK:
            raise LogoutError("Unexpected logout response: "
                              "{}".format(r.code))

        data = yield r.json()

        result = Response.from_json(**data)
        if result.Code != 1000:
            raise LoginError("Unexpected logout code: {}".format(result.Code))

    def users(self, timeout=None):
        if not self.blocking:
            return self._users()
        return crochet.run_in_reactor(self._users)().wait(timeout)

    @inlineCallbacks
    def _users(self):
        client = self.client
        headers = self.headers.copy()
        headers.update({
            'x-pm-uid': client.Uid
        })
        r = yield treq.get(
            "https://mail.protonmail.com/api/users",
            cookies=client.Cookies,
            headers=headers
        )
        response = UsersResponse.from_json(**r.json())
        if response.Code == 1000:
            client.users = [response.User]

    def settings(self, timeout=None):
        if not self.blocking:
            return self._settings()
        return crochet.run_in_reactor(self._settings)().wait(timeout)

    @inlineCallbacks
    def _settings(self):
        client = self.client
        r = yield treq.get(
            "https://mail.protonmail.com/api/settings",
            cookies=client.Cookies,
            headers={
                'Host': 'mail.protonmail.com',
                'Referer': "https://mail.protonmail.com/login/unlock",
                'Content-Type': "application/json;charset=utf-8",
                'x-pm-apiversion': client.ApiVersion,
                'x-pm-appversion': client.AppVersion,
                'x-pm-uid': client.Uid
            }
        )
        response = SettingsResponse.from_json(**r.json())
        if response.Code == 1000:
            client.settings = response.UserSettings

