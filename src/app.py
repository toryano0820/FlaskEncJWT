import base64

from flask import Flask, request, jsonify, render_template, redirect, send_from_directory, url_for, session, g
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
from encryption import AES
import email_handler
from traceback import print_exc


class DB:
    DBPool.add("db", os.environ["CONNECTION_STRING"], 4)

    @staticmethod
    def execute(target, *args, error_callback=None):
        return DBPool.execute("db", target, *args, error_callback=error_callback)

    @staticmethod
    def cursor():
        return DBPool.cursor("db")


TOKEN_TYPE = "Bearer"
TOKEN_HEADER = base64.urlsafe_b64encode('{"typ":"JWT","alg":"HS256"}'.encode()).decode()
ACCESS_EXPIRE = int(os.environ.get("ACCESS_EXPIRE", 1800))  # 1800 seconds = 30 minutes
REFRESH_EXPIRE = int(os.environ.get("REFRESH_EXPIRE", 1210000))  # 1210000 seconds  = 14 days

app = Flask(__name__)
app.secret_key = AES.get_key(os.environ.get("APP_SECRET", "thisismysecretkey"))


def generate_token(key, expire_seconds, **kwargs) -> bytes:
    now = datetime.utcnow()
    kwargs.update({
        "iat": now,
        "exp": now + timedelta(seconds=expire_seconds)
    })
    token = jwt.encode(
        payload=kwargs,
        key=key,
        algorithm="HS256"
    )

    return AES.encrypt(".".join(token.decode().split(".")[1:]), key)


def authenticate(email, password, payload=None):
    with DB.cursor() as cursor:
        cursor.callproc("authenticate", email, password, json.dumps(payload))
        row = cursor.fetchone()
        if row:
            try:
                return True, row.code
            except AttributeError:
                return False, row.error


def authorize(code):
    with DB.cursor() as cursor:
        cursor.callproc("validate_code", code)
        row = cursor.fetchone()
        if row:
            try:
                return True, row.member_id, json.loads(row.payload)
            except AttributeError:
                return False, row.error, None

        return False, "unknown_error", None


@app.route("/oauth/authorize", methods=["GET", "POST"])
def oauth_authorize():
    args = dict(request.args)
    try:
        response_type = args["response_type"]
        if response_type != "code":
            raise ValueError("response_type")
        client_id = args["client_id"]
        redirect_uri = args["redirect_uri"]
        scope = args["scope"]
        state = args["state"]
    except KeyError as ex:
        return jsonify({
            "error": "invalid_request",
            "error_description": f"required: '{ex.args[0]}'"
        }), 400

    except ValueError as ex:
        return jsonify({
            "error": "invalid_request",
            "error_description": f"invalid '{ex.args[0]}' value"
        }), 400



    with DB.cursor() as cursor:
        try:
            cursor.callproc('get_client_info', client_id)
            row = cursor.fetchone()
            app_name = row.name

        except AttributeError:
            return jsonify({"error": row.error}), 409
        except:
            print_exc()
            return jsonify({"error": "unknown_error"}), 500

    email = session.get('email', '')
    email_alert_class = session.get('email_alert_class', '')
    email_alert_message = session.get('email_alert_message', 'Valid email is required: ex@abc.xyz')
    password_alert_class = session.get('password_alert_class', '')
    password_alert_message = session.get('password_alert_message', 'Password is required')

    session.pop('email', None)
    session.pop('email_alert_class', None)
    session.pop('email_alert_message', None)
    session.pop('password_alert_class', None)
    session.pop('password_alert_message', None)

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
            if auth_data == "member_not_found":
                session['email'] = email
                session['email_alert_message'] = "Email not registered"
                session['email_alert_class'] = " alert-validate"
                return redirect(url_for('oauth_authorize') + f'?{urlencode(args)}')

            elif auth_data == "password_incorrect":
                session['email'] = email
                session['password_alert_message'] = "Password is incorrect"
                session['password_alert_class'] = " alert-validate"
                return redirect(url_for('oauth_authorize') + f'?{urlencode(args)}')

    # elif request.method == "GET":
    #     access_token = session.get('actk', None)
    #     refresh_token = session.get('rftk', None)


    return render_template(
        "login.html",
        params=urlencode(args),
        app_name=app_name,
        email=email,
        email_alert_class=email_alert_class,
        email_alert_message=email_alert_message,
        password_alert_class=password_alert_class,
        password_alert_message=password_alert_message
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
                    payload
                )
            elif grant_type == "authorization_code":
                auth_success, auth_data, auth_payload = authorize(request.form["code"])
                payload.update(auth_payload or {})

            client_id = request.form['client_id']

        except KeyError as ex:
            return jsonify({
                "error": "invalid_request",
                "error_description": f"required: '{ex.args[0]}'"
            }), 400

        if auth_success:
            with DB.cursor() as cursor:
                try:
                    cursor.callproc('get_client_info', client_id)
                    row = cursor.fetchone()
                    aes_key = AES.get_key(row.client_secret)

                except AttributeError:
                    return jsonify({"error": row.error}), 409
                except:
                    print_exc()
                    return jsonify({"error": "unknown_error"}), 500

            access_token = generate_token(
                aes_key, ACCESS_EXPIRE,
                grant_type="access_token", **payload
            )
            refresh_token = generate_token(
                app.secret_key, REFRESH_EXPIRE,
                grant_type="refresh_token", **payload
            )

            return jsonify({
                "access_token": access_token,
                "token_type": TOKEN_TYPE,
                "expires_in": ACCESS_EXPIRE,
                "refresh_token": refresh_token,
                "scope": payload["scope"]
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
                app.secret_key, ACCESS_EXPIRE,
                grant_type="access_token", **payload)

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

    with DB.cursor() as cursor:
        try:
            cursor.callproc("register_member", email, password, display_name, full_name)
            row = cursor.fetchone()
            email_handler.send_member_confirm(email, display_name, row.code)

        except AttributeError:
            return jsonify({"error": row.error}), 409

        except:
            print_exc()
            return jsonify({"error": "unknown_error"}), 500

    return jsonify({"member_id": row.member_id}), 200


@app.route("/member/code/confirm")
def member_code_confirm():
    try:
        code = request.args["code"]
    except KeyError as ex:
        return jsonify({
            "error": "invalid_request",
            "error_description": f"required: '{ex.args[0]}'"
        }), 400

    with DB.cursor() as cursor:
        try:
            cursor.callproc("validate_code", code)
            row = cursor.fetchone()
            email = row.email
            member_id = row.member_id
            display_name = row.display_name

            cursor.callproc("set_permission", email, "read")
            row = cursor.fetchone()
            permission = row.permission

        except AttributeError:
            return jsonify({"error": row.error}), 409
        except:
            print_exc()
            return jsonify({"error": "unknown_error"}), 500

    return jsonify({
        "member_id": member_id,
        "display_name": display_name,
        "email": email,
        "permission": permission
    }), 200


@app.route("/member/code/resend", methods=["POST"])
def member_code_resend():
    try:
        email = request.values["email"]
    except KeyError as ex:
        return jsonify({
            "error": "invalid_request",
            "error_description": f"required: '{ex.args[0]}'"
        }), 400

    with DB.cursor() as cursor:
        try:
            cursor.callproc("get_member_info", email)
            row = cursor.fetchone()
            display_name = row.display_name
            member_id = row.id

            cursor.callproc("generate_code", member_id, None)
            row = cursor.fetchone()
            code = row.code
            email_handler.send_member_confirm(email, display_name, code)

        except AttributeError:
            return jsonify({"error": row.error}), 409

        except:
            print_exc()
            return jsonify({"error": "unknown_error"}), 500

    return jsonify({"member_id": member_id}), 200


@app.route("/client/register", methods=["POST"])
def client_register():
    try:
        member_email = request.values["member_email"]
        name = request.values["name"]
        authorized_hosts = request.values["authorized_hosts"]
    except KeyError as ex:
        return jsonify({
            "error": "invalid_request",
            "error_description": f"required: '{ex.args[0]}'"
        }), 400

    with DB.cursor() as cursor:
        try:
            cursor.callproc("register_client", member_email, name, authorized_hosts)
            row = cursor.fetchone()

            return jsonify({
                "client_id": row.client_id,
                "client_secret": row.client_secret
            }), 200

        except AttributeError:
            return jsonify({"error": row.error}), 409

        except:
            print_exc()
            return jsonify({"error": "unknown_error"}), 500


@app.route("/client/code/confirm")
def client_code_confirm():
    try:
        code = request.args["code"]
    except KeyError as ex:
        return jsonify({
            "error": "invalid_request",
            "error_description": f"required: '{ex.args[0]}'"
        }), 400

    with DB.cursor() as cursor:
        try:
            cursor.callproc("validate_code", code)
            row = cursor.fetchone()
            email = row.email
            client_id = row.client_id
            name = row.name

            cursor.callproc("set_state", client_id, "active")
            row = cursor.fetchone()
            state = row.state

        except AttributeError:
            return jsonify({"error": row.error}), 409

        except:
            print_exc()
            return jsonify({"error": "unknown_error"}), 500

    return jsonify({
        "client_id": client_id,
        "name": name,
        "email": email,
        "state": state
    }), 200


@app.route("/client/code/resend", methods=["POST"])
def client_code_resend():
    try:
        client_id = request.values["client_id"]
    except KeyError as ex:
        return jsonify({
            "error": "invalid_request",
            "error_description": f"required: '{ex.args[0]}'"
        }), 400

    with DB.cursor() as cursor:
        try:
            cursor.callproc("get_client_info", client_id)
            row = cursor.fetchone()
            display_name = row.member_name
            email = row.email

            cursor.callproc("generate_code", client_id, None)
            row = cursor.fetchone()
            code = row.code
            email_handler.send_member_confirm(email, display_name, code)

        except AttributeError:
            return jsonify({"error": row.error}), 409

        except:
            print_exc()
            return jsonify({"error": "unknown_error"}), 500

    return jsonify({"client_id": client_id}), 200


def get_token_payload(key, token=None):
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
        jwt=TOKEN_HEADER + "." + AES.decrypt(token, key),
        key=key
    )
