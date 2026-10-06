from tests.utils import unique_string


def test_session_auth_service(client):
    username = unique_string("session_svc")
    password = "session_secret_pw"
    app_name = "SessionApp"

    # 1. Register & authenticate through session endpoint
    res = client.post(
        "/session",
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

    # 2. Access /verify introspection endpoint using the session cookie
    client.cookies.set("session_id", data["session_id"])
    verify_res = client.get("/verify")
    assert verify_res.status_code == 200
    verify_data = verify_res.json()
    assert verify_data["valid"] is True
    assert verify_data["username"] == username
    assert verify_data["auth_type"] == "session"


def test_session_via_unified_auth_endpoint(client):
    username = unique_string("unified_session")
    password = "session_pwd"
    app_name = "UnifiedApp"

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


def test_session_login_and_centralized_logout_flow(client):
    username = unique_string("session_user")
    password = "user_secret_123"
    app_name = "SessionLogoutApp"

    # 1. Authenticate / create session
    res = client.post(
        "/session",
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
    app_name = "SessionBadApp"

    # Register
    client.post(
        "/session",
        json={
            "username": username,
            "password": "correct_password",
            "app_name": app_name,
        },
    )

    # Attempt with wrong password
    bad_res = client.post(
        "/session",
        json={
            "username": username,
            "password": "wrong_password",
            "app_name": app_name,
        },
    )
    assert bad_res.status_code == 401
