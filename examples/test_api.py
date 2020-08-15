from flask import Flask, jsonify, request
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # append package folder to PYTHONPATH

import auth_service
import json


app = Flask(__name__)


def authenticate(**kwargs):
    """Validate user login

    Args:
    - **kwargs: holds login credentials/payload from API request

    Returns:
    - `list[str]`: return list of scopes
    """

    print("[DEBUG]", json.dumps(kwargs, indent=2))
    kwargs["username"]
    kwargs["password"]
    if "scope_demo" in kwargs:
        return kwargs["scope_demo"].split()
    return []


# initialize auth rules
auth_service.setup(app, authenticate, {
    "api": [
        r"^/api/.*$"
    ],
    "dev": [
        r"^/devpage$"
    ],
    "admin": [
        r"^/admin$"
    ],
})


@app.route("/test")
def hello():
    return jsonify({
        "message": "anyone can access this"
    })


@app.route("/devpage")
def developer():
    return jsonify({
        "message": f"accessible for 'dev' scope, your scopes: {auth_service.get_token_payload()['scope']}"
    })


@app.route("/api/test")
def api_test():
    return jsonify({
        "message": f"accessible for 'api' scope, your scopes: {auth_service.get_token_payload()['scope']}"
    })


@app.route("/admin")
def admin():
    return jsonify({
        "message": f"accessible for 'admin' scope, your scopes: {auth_service.get_token_payload()['scope']}"
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=8080,
        debug=True
    )
