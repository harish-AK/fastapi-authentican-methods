from tests.utils import unique_string


def test_session_auth_service(client):
    username = unique_string("session_svc")
    password = "session_secret_pw"
    app_name = unique_string("session_app")

    # 1. Register & authenticate through session endpoint (provisions api_key)
    res = client.post(
        "/session-auth",
        json={
            "username": username,
            "password": password,
            "app_name": app_name,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "registered"
    assert data["auth_type"] == "session"
    assert data["username"] == username
    assert "session_id" in data
    assert "session_id" in res.cookies
    assert "api_key" in data
    api_key = data["api_key"]
    assert api_key is not None

    # 2. Access /verify introspection endpoint using the session cookie
    client.cookies.set("session_id", data["session_id"])
    verify_res = client.get("/verify")
    assert verify_res.status_code == 200
    verify_data = verify_res.json()
    assert verify_data["valid"] is True
    assert verify_data["username"] == username
    assert verify_data["auth_type"] == "session"

    # 3. Subsequent session authentication with valid API key via header
    subsequent_res = client.post(
        "/session-auth",
        json={
            "username": username,
            "password": password,
            "app_name": app_name,
        },
        headers={"X-API-Key": api_key},
    )
    assert subsequent_res.status_code == 200

    # 4. Attempt session authentication with invalid API key
    bad_key_res = client.post(
        "/session-auth",
        json={
            "username": username,
            "password": password,
            "app_name": app_name,
            "api_key": "bad_api_key",
        },
    )
    assert bad_key_res.status_code == 401
    assert "Invalid API key" in bad_key_res.json()["detail"]


def test_session_via_unified_auth_endpoint(client):
    username = unique_string("unified_session")
    password = "session_pwd"
    app_name = unique_string("unified_session_app")

    # Call master POST /auth with auth_type="session"
    res = client.post(
        "/auth",
        json={
            "username": username,
            "password": password,
            "app_name": app_name,
            "auth_type": "session",
        },
    )
    assert res.status_code == 200
    assert res.json()["auth_type"] == "session"
    assert "session_id" in res.json()
    assert "api_key" in res.json()


def test_session_login_and_centralized_logout_flow(client):
    username = unique_string("session_user")
    password = "user_secret_123"
    app_name = unique_string("session_logout_app")

    # 1. Authenticate / create session
    res = client.post(
        "/session-auth",
        json={
            "username": username,
            "password": password,
            "app_name": app_name,
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
    username = unique_string("session_bad_pw")
    app_name = unique_string("session_bad_app")

    # Register
    reg_res = client.post(
        "/session-auth",
        json={
            "username": username,
            "password": "correct_password",
            "app_name": app_name,
        },
    )
    assert reg_res.status_code == 200
    api_key = reg_res.json()["api_key"]

    # Attempt with wrong password (supplying correct api_key)
    bad_res = client.post(
        "/session-auth",
        json={
            "username": username,
            "password": "wrong_password",
            "app_name": app_name,
            "api_key": api_key,
        },
    )
    assert bad_res.status_code == 401
    assert "Invalid credentials" in bad_res.json()["detail"]
