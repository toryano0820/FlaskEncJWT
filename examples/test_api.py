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
    - :obj:`str`: return scope as string on login success, return None otherwise
    """

    print("[DEBUG]", json.dumps(kwargs, indent=2))
    # kwargs["username"]
    # kwargs["password"]
    if "scope_demo" in kwargs:
        return kwargs["scope_demo"]
    return None


# initialize auth rules
auth_service.setup(app, authenticate, {
    "client": [
        r"^/api/.*$"
    ],
    "developer": [
        r"^/api/.*$",
        r"^/developer$"
    ],
})


@app.route("/hello")
def hello():
    return jsonify({
        "message": "Hello World!"
    })


@app.route("/developer")
def developer():
    return jsonify({
        "message": "Hello Developer!"
    })


@app.route("/api/hello")
def api_hello():
    payload = auth_service.get_token_payload()
    print(payload)
    return jsonify({
        "message": f"Hello `{payload['scope']}`!"
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=8080,
        debug=True
    )
