import base64

from flask import Flask, request, jsonify, render_template, redirect, send_from_directory, url_for, session
import jwt
import binascii
from datetime import datetime, timedelta
import os
import json
import time
import re
import traceback
from urllib.parse import urlencode

from database import DBPool
from encryption import AESCipher
from mail import send_member_confirm


class Member:
    DBPool.add("db", os.environ["CONNECTION_STRING"], 4)

    @staticmethod
    def execute(target, *args, error_callback=None):
        return DBPool.execute("db", target, *args, error_callback=error_callback)

    @staticmethod
    def cursor():
        return DBPool.cursor("db")

    @staticmethod
    def register(owner, email, password, first_name=None, last_name=None):
        with Member.cursor() as cursor:
            cursor.callproc(
                "register",
                owner, email, password, first_name, last_name
            )
            for row in cursor.fetcmany():
                return True, row.id

        return False, -1


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


def authenticate(email, password, payload):
    with Member.cursor() as cursor:
        cursor.callproc("authenticate", email, password, payload)
        row = cursor.fetchone()
        if row:
            try:
                return True, row.code
            except AttributeError:
                return False, row.error

        return False, "unknown_error"


def authorize(code):
    with Member.cursor() as cursor:
        cursor.callproc("validate_code", code)
        row = cursor.fetchone()
        if row:
            try:
                return True, row.member_id, row.payload
            except AttributeError:
                return False, row.error, None

        return False, "unknown_error", None


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
    except KeyError as ex:
        return jsonify({
            "error": "invalid_request",
            "error_description": f"required: '{ex.args[0]}'"
        }), 400

    email = ""
    email_alert_class = ""
    email_validate_message = ""
    password_alert_class = ""
    password_validate_message = ""

    if request.method == "POST":
        email = request.form["email"]
        auth_success, auth_data = authenticate(
            email,
            request.form["password"],
            {
                "client_id": client_id,
                "scope": scope
            }
        )
        if auth_success:
            return redirect(redirect_uri + "?" + urlencode({"code": auth_data, "state": state}))
        else:
            email_validate_message = ""
            password_validate_message = ""
            email_alert_class = " alert-validate"
            password_alert_class = " alert-validate"

    return render_template(
        "login.html",
        params=urlencode(dict(request.args)),
        email=email,
        email_alert_class=email_alert_class,
        email_validate_message=email_validate_message,
        password_alert_class=password_alert_class,
        password_validate_message=password_validate_message
    )


@app.route("/oauth/token")
def oauth_token():
    try:
        grant_type = request.form["grant_type"]
    except KeyError as ex:
        return jsonify({
            "error": "invalid_request",
            "error_description": f"required: '{ex.args[0]}'"
        }), 400

    if grant_type in ["password", "authorization_code"]:
        payload = dict(request.args)

        try:
            if grant_type == "password":
                auth_success, auth_data = authenticate(
                    request.form["email"],
                    request.form["password"],
                    None
                )
                payload.update({
                    "client_id": request.args["client_id"],
                    "scope": request.args["scope"]
                })
            elif grant_type == "authorization_code":
                auth_success, auth_data, auth_payload = authorize(request.form["code"])
                payload.update(auth_payload)
        except KeyError as ex:
            return jsonify({
                "error": "invalid_request",
                "error_description": f"required: '{ex.args[0]}'"
            }), 400

        if auth_success:
            access_token = generate_token(
                ACCESS_EXPIRE, grant_type="access_token", **payload)
            refresh_token = generate_token(
                REFRESH_EXPIRE, grant_type="refresh_token", **payload)

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
                "error_description": f"{'authentication' if grant_type == 'password' else 'authorization'} failed: {auth_data}"
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


@app.route("/member/register", methods=["POST"])
def member_register():
    try:
        email = request.values["email"]
        password = request.values["password"]
        display_name = None if "display_name" not in request.values else request.values["display_name"]
        full_name = None if "full_name" not in request.values else request.values["full_name"]
    except KeyError as ex:
        return jsonify({
            "error": "invalid_request",
            "error_description": f"required: '{ex.args[0]}'"
        }), 400

    with Member.cursor() as cursor:
        cursor.callproc("register_member", email, password, display_name, full_name)
        row = cursor.fetchone()
        if row:
            try:
                code = row.code
                send_member_confirm(email, display_name, code)
                return jsonify({"member_id": row.member_id}), 200
            except AttributeError:
                return jsonify({"error": row.error}), 409

    return jsonify({"error": "unknown_error"}), 500


@app.route("/member/confirm")
def member_confirm():
    code = request.args["code"]

    with Member.cursor() as cursor:
        cursor.callproc("validate_code", code)
        try:
            for row in cursor:
                email = row.email
                member_id = row.member_id
                display_name = row.display_name
                break
        except AttributeError:
            return jsonify({"error": row.error}), 409
        except:
            return jsonify({"error": "unknown_error"}), 500

        cursor.callproc("add_scope", email, "read")
        try:
            for row in cursor:
                scope = row.scope
                break
        except AttributeError:
            return jsonify({"error": row.error}), 409
        except:
            return jsonify({"error": "unknown_error"}), 500

        return jsonify({
            "member_id": member_id,
            "display_name": display_name,
            "email": email,
            "scope": scope
        }), 200


@app.route("/client/register", methods=["POST"])
def client_register():
    try:
        client_id = request.values["client_id"]
        name = request.values["name"]
        redirect_uri = request.values["redirect_uri"]
        description = None if "description" not in request.values else request.values["description"]
    except KeyError as ex:
        return jsonify({
            "error": "invalid_request",
            "error_description": f"required: '{ex.args[0]}'"
        }), 400

    with Member.cursor() as cursor:
        cursor.callproc("register_client", client_id, name, description, redirect_uri)
        row = cursor.fetchone()
        if row:
            try:
                return jsonify({"client_id": row.id}), 200
            except AttributeError:
                return jsonify({"error": row.error}), 409

    return jsonify({"error": "unknown_error"}), 500


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


def get_token_payload(token=None):
    """Get payload dict from token

    Args:
    - token (:obj:`str`, optional): Token string, will use Authorization header token if none given.

    Returns:
    - `dict`: Payload passed on login.
    """

    if token is None:
        if "payload" in g:
            return g.payload

        auth_header = request.headers["Authorization"]
        token_header = TOKEN_TYPE + " "

        if auth_header[:len(token_header)] != token_header:
            raise ValueError()

        token = auth_header[len(token_header):]

    return jwt.decode(
        jwt=TOKEN_HEADER + "." + aes_cipher.decrypt(token),
        key=app.secret_key
    )


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
    # app.run(
    #     host="0.0.0.0",
    #     port=80
    # )
    Member.register("a", "kpphtl@gmail.com", "Cr123456")
