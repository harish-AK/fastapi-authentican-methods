from tests.utils import unique_string


def test_session_auth_service(client):
    username = unique_string("session_svc")
    email = f"{username}@example.com"
    password = "session_secret_pw"
    app_id = 201

    # 1. Register & authenticate through session-auth service
    res = client.post(
        "/session-auth",
        json={
            "app_id": app_id,
            "username": username,
            "password": password,
            "email": email,
            "app_name": "Session App",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "registered"
    assert data["username"] == username
    assert "session_id" in data
    assert "session_id" in res.cookies

    # 2. Access protected profile using the session cookie
    client.cookies.set("session_id", data["session_id"])
    profile_res = client.get("/profile")
    assert profile_res.status_code == 200
    profile_data = profile_res.json()
    assert profile_data["username"] == username
    assert profile_data["email"] == email


def test_session_login_and_centralized_logout_flow(client):
    username = unique_string("session_user")
    email = f"{username}@example.com"
    password = "user_secret_123"
    app_id = 202

    # 1. Create user
    client.post(
        "/session-auth",
        json={
            "app_id": app_id,
            "username": username,
            "password": password,
            "email": email,
        },
    )

    # 2. Log in using /login
    login_res = client.post(
        "/login",
        json={
            "username": username,
            "password": password,
        },
    )
    assert login_res.status_code == 200
    assert "session_id" in login_res.cookies
    session_id = login_res.cookies["session_id"]

    # 3. Access protected profile with the session cookie
    client.cookies.set("session_id", session_id)
    profile_res = client.get("/profile")
    assert profile_res.status_code == 200
    assert profile_res.json()["username"] == username

    # 4. Centralized logout calling /logout with username
    logout_res = client.post(
        "/logout",
        json={"username": username},
    )
    assert logout_res.status_code == 200
    assert "logged out successfully" in logout_res.json()["message"]

    # 5. Accessing protected profile with old session cookie must now fail
    client.cookies.set("session_id", session_id)
    denied_res = client.get("/profile")
    assert denied_res.status_code == 401
    assert denied_res.json()["detail"] == "Invalid session"


def test_session_invalid_login(client):
    res = client.post(
        "/login",
        json={
            "username": "non_existent_user_999",
            "password": "wrong_password",
        },
    )
    assert res.status_code == 401


def test_profile_unauthorized_without_cookie(client):
    res = client.get("/profile")
    assert res.status_code == 401
    assert res.json()["detail"] == "Session not found"
