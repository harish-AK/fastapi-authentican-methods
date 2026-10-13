from tests.utils import unique_string


def test_basic_auth_service_registration_and_login(client):
    username = unique_string("basic_user")
    email = f"{username}@example.com"
    password = "secretpassword123"
    app_name = unique_string("basic_app")

    # 1. Register a new user via basic auth endpoint (generates api_key)
    register_res = client.post(
        "/basic-auth",
        json={
            "username": username,
            "password": password,
            "email": email,
            "app_name": app_name,
        },
    )
    assert register_res.status_code == 200
    data = register_res.json()
    assert data["status"] == "registered"
    assert data["auth_type"] == "basic"
    assert data["username"] == username
    assert data["email"] == email
    assert data["app_name"] == app_name
    assert "user_id" in data
    assert "api_key" in data
    api_key = data["api_key"]
    assert api_key is not None

    # 2. Existing user logs in / verifies with credentials and api_key in payload
    login_res = client.post(
        "/basic-auth",
        json={
            "username": username,
            "password": password,
            "app_name": app_name,
            "api_key": api_key,
        },
    )
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert login_data["status"] == "verified"
    assert login_data["username"] == username

    # 3. Existing app login using X-API-Key header
    header_res = client.post(
        "/basic-auth",
        json={
            "username": username,
            "password": password,
            "app_name": app_name,
        },
        headers={"X-API-Key": api_key},
    )
    assert header_res.status_code == 200

    # 4. Existing app with invalid API key rejected
    bad_key_res = client.post(
        "/basic-auth",
        json={
            "username": username,
            "password": password,
            "app_name": app_name,
            "api_key": "invalid_api_key",
        },
    )
    assert bad_key_res.status_code == 401
    assert "Invalid API key" in bad_key_res.json()["detail"]

    # 5. Existing app with missing API key rejected
    missing_key_res = client.post(
        "/basic-auth",
        json={
            "username": username,
            "password": password,
            "app_name": app_name,
        },
    )
    assert missing_key_res.status_code == 401
    assert "API key is required" in missing_key_res.json()["detail"]


def test_basic_auth_via_unified_auth_endpoint(client):
    username = unique_string("unified_basic")
    password = "unified_password"
    app_name = unique_string("unified_app")

    # Calling master POST /auth with auth_type="basic"
    res = client.post(
        "/auth",
        json={
            "username": username,
            "password": password,
            "app_name": app_name,
            "auth_type": "basic",
        },
    )
    assert res.status_code == 200
    assert res.json()["auth_type"] == "basic"
    assert res.json()["status"] == "registered"
    assert "api_key" in res.json()


def test_basic_auth_service_invalid_password(client):
    username = unique_string("basic_badpw")
    app_name = unique_string("bad_pw_app")

    # Register
    reg_res = client.post(
        "/basic-auth",
        json={
            "username": username,
            "password": "correct_password",
            "app_name": app_name,
        },
    )
    assert reg_res.status_code == 200
    api_key = reg_res.json()["api_key"]

    # Attempt login with wrong password
    bad_res = client.post(
        "/basic-auth",
        json={
            "username": username,
            "password": "wrong_password",
            "app_name": app_name,
            "api_key": api_key,
        },
    )
    assert bad_res.status_code == 401
    assert "Invalid credentials" in bad_res.json()["detail"]
