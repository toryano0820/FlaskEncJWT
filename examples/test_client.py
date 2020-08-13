import time
import requests


while True:
    print("[INFO] Try logging-in with predefined credentials")
    # login: request access token and refresh token
    login_rsp = requests.get(
        "http://localhost:8080/oauth/token",
        data={
            "grant_type": "password",
            "username": "myusername",
            "password": "mypassword",
            "scope_demo": "developer"  # for testing only ('client'|'developer')
        }
    )
    login_data = login_rsp.json()
    print("[DEBUG]", login_data)

    if login_rsp.status_code == 200:
        refresh_token = login_data["refresh_token"]
        access_token = login_data["access_token"]
        token_type = login_data["token_type"]
    else:  # login failed
        break  # exit application

    while True:
        input()
        print("[INFO] Try getting secured data")
        api_rsp = requests.get(
            "http://localhost:8080/developer",
            # "http://localhost:8080/api/hello",
            headers={
                "Authorization": f"{token_type} {access_token}"
            }
        )
        print("[DEBUG]", api_rsp.json())

        if api_rsp.status_code == 401:  # access token expired
            print("[INFO] Try refreshing access_token")
            # request new access token
            refresh_rsp = requests.get(
                "http://localhost:8080/oauth/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token
                }
            )
            refresh_data = refresh_rsp.json()
            print("[DEBUG]", refresh_data)

            if refresh_rsp.status_code == 200:
                access_token = refresh_data["access_token"]
                token_type = refresh_data["token_type"]
            else:  # refresh token expired
                break  # go back to login
