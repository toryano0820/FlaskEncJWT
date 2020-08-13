from flask import Flask, jsonify
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # append package folder to PYTHONPATH

import auth_service
import json


app = Flask(__name__)


def authenticate(**kwargs):
    print("[DEBUG]", json.dumps(kwargs, indent=2))
    return True


auth_service.setup(app, authenticate, [r"^/api/.*$"])  # initialize auth rules


@app.route("/hello")
def hello():
    return jsonify({
        "message": "Hello World!"
    })


@app.route("/api/hello")
def api_hello():
    return jsonify({
        "message": "Hello API World!"
    })


if __name__ == "__main__":
    app.run(
        port=8080,
        debug=True
    )
