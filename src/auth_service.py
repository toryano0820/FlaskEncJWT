from Crypto.Cipher import AES
from Crypto import Random
import base64
import hashlib

from flask import Flask, request, jsonify, render_template, redirect, send_from_directory
import jwt
import binascii
from datetime import datetime, timedelta
import os
import json
import time
import re
import traceback
from urllib.parse import urlencode

import sqlite3
from contextlib import contextmanager


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


TOKEN_TYPE = "Bearer"
TOKEN_HEADER = base64.urlsafe_b64encode('{"typ":"JWT","alg":"HS256"}'.encode()).decode()
ACCESS_EXPIRE = int(os.environ.get("_ACCESS_EXPIRE", 1800))  # 1800 seconds = 30 minutes
REFRESH_EXPIRE = int(os.environ.get("_REFRESH_EXPIRE", 1210000))  # 1210000 seconds  = 14 days

app = Flask(__name__)
app.secret_key = os.environ.get("_APP_KEY", "thisismysecretkey")
aes_cipher = AESCipher(app.secret_key)
secured_endpoint_match = {}
auth_func = None


def generate_token(expire_seconds, **kwargs) -> bytes:
    t = time.time()
    now = datetime.utcnow()
    kwargs.update({
        "iat": now,
        "exp": now + timedelta(seconds=expire_seconds)
    })
    token = jwt.encode(
        payload=kwargs,
        key=app.secret_key,
        algorithm="HS256"
    )

    return aes_cipher.encrypt(".".join(token.decode().split(".")[1:]))


def authenticate(*args, **kwargs):
    return False


@app.route("/oauth/authorize", methods=["GET", "POST"])
def oauth_authorize():
    try:
        response_type = request.args["response_type"]
        if response_type != "code":
            raise KeyError("response_type=code")
        client_id = request.args["client_id"]
        redirect_uri = request.args["redirect_uri"]
        scope = request.args["scope"]
        state = request.args["state"]
        alert_class = ""
    except KeyError as ex:
        return jsonify({
            "error": "invalid_request",
            "error_description": f"required: '{ex.args[0]}'"
        }), 400

    if request.method == "POST":
        if authenticate():  # TODO: login condition
            return redirect(redirect_uri)
        else:
            alert_class = " alert-validate"

    return render_template("login.html", params=urlencode(dict(request.args)), alert_class=alert_class)


@app.route("/oauth/token")
def oauth_token():
    try:
        grant_type = request.values["grant_type"]
    except KeyError as ex:
        return jsonify({
            "error": "invalid_request",
            "error_description": f"required: '{ex.args[0]}'"
        }), 400

    if grant_type == "password":
        payload = dict(request.values)

        try:
            scope = auth_func(**payload)
        except KeyError as ex:
            return jsonify({
                "error": "invalid_request",
                "error_description": f"required: '{ex.args[0]}'"
            }), 400

        del payload["grant_type"]

        if scope:
            access_token = generate_token(
                ACCESS_EXPIRE, grant_type="access_token", scope=scope, **payload)
            refresh_token = generate_token(
                REFRESH_EXPIRE, grant_type="refresh_token", scope=scope, **payload)

            return jsonify({
                "access_token": access_token,
                "token_type": TOKEN_TYPE,
                "expires_in": ACCESS_EXPIRE,
                "refresh_token": refresh_token,
                "scope": scope
            }), 200
        else:
            return jsonify({
                "error": "invalid_client",
                "error_description": "authentication failed"
            }), 400

    elif grant_type == "refresh_token":
        try:
            try:
                payload = get_token_payload(request.values["refresh_token"])
            except KeyError as ex:
                return jsonify({
                    "error": "invalid_request",
                    "error_description": f"required: '{ex.args[0]}'"
                }), 400

            if payload["grant_type"] != "refresh_token":
                raise jwt.exceptions.InvalidTokenError()

            del payload["grant_type"]

            access_token = generate_token(
                ACCESS_EXPIRE, grant_type="access_token", **payload)

            return jsonify({
                "token_type": TOKEN_TYPE,
                "access_token": access_token,
                "expires_in": ACCESS_EXPIRE
            }), 200

        except jwt.exceptions.ExpiredSignatureError:
            return jsonify({
                "error": "token_expired",
                "error_description": "token expired"
            }), 401

        except (jwt.exceptions.InvalidTokenError, binascii.Error, KeyError, UnicodeDecodeError, ValueError) as ex:
            return jsonify({
                "error": "invalid_token",
                "error_description": "invalid token"
            }), 401

        except Exception as ex:
            return jsonify({
                "error": "server_error",
                "error_description": str(ex).split(":")[0]
            }), 500

    else:
        return jsonify({
            "error": "unsupported_grant_type",
            "error_description": f"unknown grant_type: '{grant_type}'"
        }), 400


# @app.before_app_request
# def access_validator():
#     if secured_endpoint_match and re.match("|".join(secured_endpoint_match.values()), request.path):
#         authorized = False
#         if "Authorization" in request.headers:
#             try:
#                 payload = get_token_payload()

#                 if payload["grant_type"] != "access_token":
#                     raise jwt.exceptions.InvalidTokenError()

#                 for scope in payload["scope"]:
#                     if scope in secured_endpoint_match and re.match(secured_endpoint_match[scope], request.path):
#                         g.payload = payload
#                         authorized = True
#                         break
#                 else:
#                     return jsonify({
#                         "error": "access_denied",
#                         "error_description": "invalid scope"
#                     }), 403

#             except jwt.exceptions.ExpiredSignatureError:
#                 return jsonify({
#                     "error": "token_expired",
#                     "error_description": "token expired"
#                 }), 401

#             except (jwt.exceptions.InvalidTokenError, binascii.Error, KeyError, UnicodeDecodeError):
#                 return jsonify({
#                     "error": "invalid_token",
#                     "error_description": "invalid token"
#                 }), 401

#             except ValueError:
#                 return jsonify({
#                     "error": "invalid_request",
#                     "error_description": "malformed authorization header"
#                 }), 400

#             except Exception as ex:
#                 traceback.print_exc()
#                 return jsonify({
#                     "error": "server_error",
#                     "error_description": str(ex).split(":")[0]
#                 }), 500

#         if not authorized:
#             return jsonify({
#                 "error": "access_denied",
#                 "error_description": "access denied"
#             }), 400


# def get_token_payload(token=None):
#     """Get payload dict from token

#     Args:
#     - token (:obj:`str`, optional): Token string, will use Authorization header token if none given.

#     Returns:
#     - `dict`: Payload passed on login.
#     """

#     if token is None:
#         if "payload" in g:
#             return g.payload

#         auth_header = request.headers["Authorization"]
#         token_header = TOKEN_TYPE + " "

#         if auth_header[:len(token_header)] != token_header:
#             raise ValueError()

#         token = auth_header[len(token_header):]

#     return jwt.decode(
#         jwt=TOKEN_HEADER + "." + aes_cipher.decrypt(token),
#         key=app.secret_key
#     )


# def setup(flask_app, login_func, endpoint_patterns={}):
#     """Integrates this auth plugin into existing Flask instance

#     Args:
#     - flask_app (`Flask`): Flask app to integrate this plugin
#     - login_func (`callable`): Function where login params are passed, must return scope `str` on success or `None` on login failure
#     - endpoint_patterns (`dict[str, list[str]]`): Scope dict with list of RegEx patterns for secured endpoints
#    """
#     global auth_func
#     auth_func = login_func
#     for scope in endpoint_patterns:
#         secured_endpoint_match[scope] = "|".join(endpoint_patterns[scope])
#     flask_app.register_blueprint(app)


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=80,
        debug=True
    )
