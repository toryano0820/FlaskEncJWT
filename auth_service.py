'''
Resource Owner Password Flow
'''

from Crypto.Cipher import AES
from Crypto import Random
import base64
import hashlib

from flask import Flask, Blueprint, request, jsonify
import jwt
import binascii
from datetime import datetime, timedelta
import os
import json
import time
import re
import traceback


class AESCipher:
    '''
    https://stackoverflow.com/a/21928790
    '''
    def __init__(self, key):
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, text):
        text = AESCipher._pad(text)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(text.encode())).decode()

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return AESCipher._unpad(cipher.decrypt(enc[AES.block_size:])).decode()

    @staticmethod
    def _pad(s):
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]


__app = Blueprint("auth_service", __name__)
__app.secret_key = os.environ.get("_APP_KEY", "thisismysecretkey")
__access_expire = int(os.environ.get("_ACCESS_EXPIRE", 1800))  # 1800 seconds = 30 minutes
__refresh_expire = int(os.environ.get("_REFRESH_EXPIRE", 1210000))  # 1210000 seconds  = 14 days
__aes_cipher = AESCipher(__app.secret_key)
__token_type = "Bearer"
__secured_endpoint_match = []
__auth_func = None


def __generate_token(expire_seconds, **kwargs) -> bytes:
    t = time.time()
    now = datetime.utcnow()
    kwargs.update({
        "iat": now,
        "exp": now + timedelta(seconds=expire_seconds)
    })
    token = jwt.encode(
        payload=kwargs,
        key=__app.secret_key,
        algorithm="HS256"
    )

    return __aes_cipher.encrypt(token.decode())


@__app.route("/oauth/token")
def __auth_token():
    try:
        grant_type = request.values["grant_type"]
    except KeyError:
        return jsonify({
            "error": "parameter_absent"
        }), 400

    if grant_type == "password":
        payload = dict(request.values)

        try:
            authenticated = __auth_func(**payload)
        except KeyError:
            return jsonify({
                "error": "parameter_absent"
            }), 400

        del payload["password"]
        del payload["grant_type"]

        if authenticated:
            access_token = __generate_token(__access_expire, grant_type="access_token", **payload)
            refresh_token = __generate_token(__refresh_expire, grant_type="refresh_token", **payload)

            return jsonify({
                "token_type": __token_type,
                "access_token": access_token,
                "expires_in": __access_expire,
                "refresh_token": refresh_token
            }), 200
        else:
            return jsonify({
                "error": "invalid_client"
            }), 400

    elif grant_type == "refresh_token":
        try:
            try:
                refresh_token = __aes_cipher.decrypt(request.values["refresh_token"])
            except KeyError:
                return jsonify({
                    "error": "parameter_absent"
                }), 400

            payload = jwt.decode(
                jwt=refresh_token,
                key=__app.secret_key
            )

            if payload["grant_type"] != "refresh_token":
                raise KeyError()

            del payload["grant_type"]

            access_token = __generate_token(__access_expire, grant_type="access_token", **payload)

            return jsonify({
                "token_type": __token_type,
                "access_token": access_token,
                "expires_in": __access_expire
            }), 200

        except (binascii.Error, KeyError, UnicodeDecodeError):
            return jsonify({
                "error": "invalid_token"
            }), 401

        except jwt.exceptions.ExpiredSignatureError:
            return jsonify({
                "error": "token_expired"
            }), 401

        except Exception as ex:
            return jsonify({
                "error": str(ex).split(":")[0]
            }), 500

    else:
        return jsonify({
            "error": "unsupported_grant_type"
        }), 400


# @__app.route("/oauth/parse_token")
# def api_token():
#     token = request.values["token"]
#     token = __aes_cipher.decrypt(token)
#     payload = jwt.decode(
#         jwt=token,
#         key=__app.secret_key
#     )
#     return jsonify(payload), 200


@__app.before_app_request
def __access_validator():
    if __secured_endpoint_match and re.match(__secured_endpoint_match, request.path):
        authorized = False
        if "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            if auth_header.startswith(__token_type + " "):
                try:
                    access_token = __aes_cipher.decrypt(auth_header[len(__token_type) + 1:])

                    payload = jwt.decode(
                        jwt=access_token,
                        key=__app.secret_key
                    )

                    if payload["grant_type"] != "access_token":
                        raise KeyError()

                    authorized = True
                except (binascii.Error, KeyError, UnicodeDecodeError):
                    return jsonify({
                        "error": "invalid_token"
                    }), 401

                except jwt.exceptions.ExpiredSignatureError:
                    return jsonify({
                        "error": "token_expired"
                    }), 401

                except Exception as ex:
                    traceback.print_exc()
                    return jsonify({
                        "error": str(ex).split(":")[0]
                    }), 500

        if not authorized:
            return jsonify({
                "error": "access_denied"
            }), 400


def setup(flask_app, login_func, endpoint_patterns=[]):
    """Integrates this auth plugin into existing Flask instance

    Parameters:

    flask_app (`Flask`): Flask app to integrate this plugin

    login_func (`callable`): Function where login params are passed, must return `bool`

    endpoint_patterns (`list[str]`): RegEx patterns for secured endpoint
   """
    global __secured_endpoint_match, __auth_func
    __auth_func = login_func
    __secured_endpoint_match = "|".join(__secured_endpoint_match + endpoint_patterns)
    flask_app.register_blueprint(__app)
