from tests.utils import unique_string


def test_session_auth_service(client):
    app_name = unique_string("session_app")
    username = unique_string("session_svc")
    password = "session_secret_pw"

    # 1. Register application once to receive api_key
    app_res = client.post("/apps/register", json={"app_name": app_name})
    assert app_res.status_code == 201
    api_key = app_res.json()["api_key"]

    # 2. Register & authenticate user through session endpoint using X-API-Key
    res = client.post(
        "/session-auth",
        headers={"X-API-Key": api_key},
        json={
            "username": username,
            "password": password,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "registered"
    assert data["auth_type"] == "session"
    assert data["username"] == username
    assert "session_id" in data
    assert "session_id" in res.cookies
    assert "api_key" not in data

    # 3. Access /verify introspection endpoint using the session cookie
    client.cookies.set("session_id", data["session_id"])
    verify_res = client.get("/verify")
    assert verify_res.status_code == 200
    verify_data = verify_res.json()
    assert verify_data["valid"] is True
    assert verify_data["username"] == username
    assert verify_data["auth_type"] == "session"

    # 4. Subsequent session authentication with valid API key via header
    subsequent_res = client.post(
        "/session-auth",
        headers={"X-API-Key": api_key},
        json={
            "username": username,
            "password": password,
        },
    )
    assert subsequent_res.status_code == 200

    # 5. Attempt session authentication with invalid API key
    bad_key_res = client.post(
        "/session-auth",
        headers={"X-API-Key": "bad_api_key"},
        json={
            "username": username,
            "password": password,
        },
    )
    assert bad_key_res.status_code == 401
    assert "Invalid API key" in bad_key_res.json()["detail"]



def test_session_login_and_centralized_logout_flow(client):
    app_name = unique_string("session_logout_app")
    username = unique_string("session_user")
    password = "user_secret_123"

    # Register app
    app_res = client.post("/apps/register", json={"app_name": app_name})
    assert app_res.status_code == 201
    api_key = app_res.json()["api_key"]

    # 1. Authenticate / create session
    res = client.post(
        "/session-auth",
        headers={"X-API-Key": api_key},
        json={
            "username": username,
            "password": password,
        },
    )
    assert res.status_code == 200
    session_id = res.json()["session_id"]

    # 2. Verify active session works
    client.cookies.set("session_id", session_id)
    verify_res = client.get("/verify")
    assert verify_res.status_code == 200
    assert verify_res.json()["username"] == username

    # 3. Centralized logout calling /logout with username
    logout_res = client.post(
        "/logout",
        json={"username": username, "app_name": app_name},
    )
    assert logout_res.status_code == 200
    assert "logged out successfully" in logout_res.json()["message"]

    # 4. Accessing /verify with old session cookie must now fail
    client.cookies.set("session_id", session_id)
    denied_res = client.get("/verify")
    assert denied_res.status_code == 401


def test_session_invalid_password(client):
    app_name = unique_string("session_bad_app")
    username = unique_string("session_bad_pw")

    # Register app
    app_res = client.post("/apps/register", json={"app_name": app_name})
    assert app_res.status_code == 201
    api_key = app_res.json()["api_key"]

    # Register user
    reg_res = client.post(
        "/session-auth",
        headers={"X-API-Key": api_key},
        json={
            "username": username,
            "password": "correct_password",
        },
    )
    assert reg_res.status_code == 200

    # Attempt with wrong password
    bad_res = client.post(
        "/session-auth",
        headers={"X-API-Key": api_key},
        json={
            "username": username,
            "password": "wrong_password",
        },
    )
    assert bad_res.status_code == 401
    assert "Invalid credentials" in bad_res.json()["detail"]
