"""
Copyright (c) 2018, Jairus Martin.

Distributed under the terms of the BSD License.

The full license is in the file LICENSE, distributed with this software.

Created on May, 2018
"""
import os
import pgpy
import random
import bcrypt
import binascii
from bcrypt import _bcrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from pgpy import PGPMessage, PGPKey
from pgpy.constants import SymmetricKeyAlgorithm
from pgpy.packet import PKESessionKeyV3


def read_armored(message):
    """ Read an OpenPGP signed cleartext message
    
    Parameters
    ----------
    message: String
        OpenPGP signed message

    Returns
    -------
    message: String
        Message contents

    """
    # It's is not a valid OpenPGP message so screw it it
    return message.strip().split("\n")[3]


def bcrypt_encode_base64(salt, n=16):
    """ Python impl of dcodeIO.bcrypt.encodeBase64(saltBinary, 16)
    
    """
    if 0 > len(salt) > n:
        # base64.js throws an error if this happens
        raise KeyError("Illegal salt length: {}".format(len(salt)))
    output = _bcrypt.ffi.new("char[]", 30)  # TODO: Where does 30 come from?
    _bcrypt.lib.encode_base64(output, bytes(salt), len(salt))
    return _bcrypt.ffi.string(output)


def hash_password(auth_version, password, salt, username, modulus):
    """ Generates the hashed password for authentication
    
    Parameters
    ----------
    auth_version: Int
    password: String or Bytes
    salt: String or Bytes
    username: String or Bytes
    modulus: Bytes

    Returns
    -------
    result: String or Bytes
        Hashed password

    """
    if auth_version in (3, 4):
        bsalt = bytes(salt) + b'proton'
        key = bcrypt.hashpw(password, b'$2y$10$'+bcrypt_encode_base64(bsalt))
        return hash(key + modulus)
    else:
        raise NotImplementedError("Only v3+ is currently implemented")


def compute_key_password(password, salt):
    """ Computes the password for unlocking the access token
    
    Parameters
    ----------
    password: String
    salt: String
    
    Returns
    -------
    hashed: String

    """
    return bcrypt.hashpw(password, b'$2y$10$'+bcrypt_encode_base64(salt))[29:]


def check_mailbox_password(key, password, access_token):
    """ Make sure the password is valid by decrypting the access token.
    
    Parameters
    ----------
    key: Bytes
        PGP Private key
    password: String
    access_token: String
        Access token as an encrypted PGP message 
    Returns
    -------
    token: String

    """
    if not key:
        raise ValueError("Missing private key")
    if not password:
        raise ValueError("Missing password")
    if not access_token:
        raise ValueError("Missing access token")
    msg = PGPMessage.from_blob(access_token)
    pk, _ = PGPKey.from_blob(key)
    with pk.unlock(password) as uk:
        return bytes(uk.decrypt(msg).message)


def sha512(x):
    """ Computes sha512 of the given string or bytes
    
    Parameters
    ----------
    x: String or Bytes
        Input to hash
    
    Returns
    -------
    y: Bytes
        Hashed value
    
    """
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(x)
    return digest.finalize()


def hash(x):
    """ Hash function based on expandHash and srpHash from the WebClient 
    
    Parameters
    ----------
    x: String or Bytes
        Input to hash

    Returns
    -------
    y: Bytes
        Hashed value
    
    """
    return b''.join((sha512(x+b'\x00'), sha512(x+b'\x01'), sha512(x+b'\x02'),
                     sha512(x+b'\x03')))


def to_bn(arr):
    """ Convert bytes to an integer
    
    Parameters
    ----------
    arr: Bytes
    
    Returns
    -------
    result: Int
    
    """
    return int(binascii.hexlify(bytearray(reversed(arr))), 16)


def from_bn(i, n=2048/8):
    """ Convert an integer to bytes of length n
    
    Parameters
    ----------
    i: Int
    
    Returns
    -------
    arr: Bytes
    
    """
    return bytes(bytearray([(i & (0xff << pos*8)) >> pos*8
                            for pos in range(n)]))


def mod_reduce(a, b):
    """ Based on asmCrypto.Modulus.reduce """
    if a > b:
        a = a % b
    return a


def generate_random_bytes(n):
    """ Pulled out for testing purposes """
    return os.urandom(n)


def generate_random_string(n):
    """ Generate a random string of length n """
    cs = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    return ''.join(random.SystemRandom().choice(cs) for _ in range(n))


def generate_proofs(key_size, modulus, hashed_password, server_ephemeral):
    """ Generate the Proofs. Ported from the WebClient
    
    Parameters
    ----------
    key_size: Int
    modulus: Int
    hashed_password: String
    server_ephemeral: String

    Returns
    -------
    proofs: Dict
        Contains the client and expect server proofs and the client ephemeral
        
    """
    g = 2
    multiplier = to_bn(hash(from_bn(g)+modulus))
    p = to_bn(modulus)
    y = to_bn(server_ephemeral)
    hpw = to_bn(hashed_password)
    modulus_minus_one = p-1

    # Modular reduction
    multiplier = mod_reduce(multiplier, p)

    if p.bit_length() not in (key_size, key_size-1):
        raise KeyError('SRP modulus has incorrect size')
    if 1 > multiplier > modulus_minus_one:
        raise KeyError('SRP multiplier is out of bounds')
    if 1 > g > modulus_minus_one:
        raise KeyError('SRP generator is out of bounds')
    if 1 > y > modulus_minus_one:
         raise KeyError('SRP server ephemeral is out of bounds')

    # Create a seed
    def gen_secret():
        n = key_size/8
        client_secret = generate_random_bytes(n)
        # If too small, retry
        while to_bn(client_secret) < key_size * 2:
            client_secret = generate_random_bytes(n)
        return client_secret

    def gen_params():
        client_secret = gen_secret()
        client_ephemeral = from_bn(pow(g, to_bn(client_secret), p))
        scrambling_param = hash(client_ephemeral+server_ephemeral)
        return client_secret, client_ephemeral, scrambling_param

    #
    client_secret, client_ephemeral, scrambling_param = gen_params()
    while scrambling_param == 0:
        client_secret, client_ephemeral, scrambling_param = gen_params()

    subtracted = y - mod_reduce(pow(g, hpw, p)*multiplier, p)
    if subtracted < 0:
        subtracted += p

    exponent = (to_bn(scrambling_param) * hpw +
                to_bn(client_secret)) % modulus_minus_one
    shared_session = from_bn(pow(subtracted, exponent, p))

    client_proof = hash(client_ephemeral + server_ephemeral + shared_session)
    server_proof = hash(client_ephemeral + client_proof + shared_session)
    return {
        'client_ephemeral': client_ephemeral,
        'client_proof': client_proof,
        'server_proof': server_proof
    }


def generate_session_key(cipher=SymmetricKeyAlgorithm.AES256):
    """ Generate an AES256 session key for the given cipher 
    
    Parameters
    ----------
    cipher: pgpy.constants.SymmetricKeyAlgorithm
        Cipher to use generate a key for
       
    Returns
    -------
    result: Bytes
        Generated key
        
    """
    return cipher.gen_key()


def encrypt_session_key(session_key, key=None, password=None, 
                        cipher=SymmetricKeyAlgorithm.AES256):
    """ Encrypts a session key for sending with the message to other proton
    mail clients.
    
    Parameters
    ----------
    session_key: Bytes
        Session key for sending messages to multiple recipients.
    key: pgpy.PGPKey
        Recipient to encrypt the key for
    password: String or Bytes
        Password to encrypt the key with
    cipher: pgpy.constants.SymmetricKeyAlgorithm
        Cipher to use for encryption
    
    Returns
    -------
    result: Bytes
        Encrypted session key data
        
    """
    if key:
        pkt = PKESessionKeyV3()
        pkt.encrypter = bytearray(binascii.unhexlify(
                            key.fingerprint.keyid.encode('latin-1')))
        pkt.pkalg = key.key_algorithm
        pkt.encrypt_sk(key._key, cipher, session_key)
        return pkt.__bytes__()
    else:
        raise NotImplementedError
    

def decrypt_session_key(blob, key=None, password=None):
    """ Decrypt the session key from the given PGPMessage blob
    
    Parameters
    ----------
    blob: String or Bytes
        PGP Message data
    key: pgpy.PGPKey
        The private PGPKey for decryption. It MUST be unlocked.
    password: String or Bytes
        The password for decryption
    
    Returns
    -------
    result: Tuple[pgpy.constants.SymmetricKeyAlgorithm, Bytes]
        The algo and session key
    
    """
    message = PGPMessage.from_blob(blob)
    for sk in message._sessionkeys:
        k = key._children.get(sk.encrypter)
        if k is not None:
            cipher, session_key = sk.decrypt_sk(k._key)
            return cipher, bytes(session_key)
    raise KeyError("Key not found")
