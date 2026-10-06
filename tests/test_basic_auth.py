from tests.utils import unique_string


def test_basic_auth_service_registration_and_login(client):
    username = unique_string("basic_user")
    email = f"{username}@example.com"
    password = "secretpassword123"
    app_name = "BasicApp"

    # 1. Register a new user via basic auth endpoint
    register_res = client.post(
        "/basic",
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

    # 2. Existing user logs in / verifies with the same credentials
    login_res = client.post(
        "/basic",
        json={
            "username": username,
            "password": password,
            "app_name": app_name,
        },
    )
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert login_data["status"] == "verified"
    assert login_data["username"] == username


def test_basic_auth_via_unified_auth_endpoint(client):
    username = unique_string("unified_basic")
    password = "unified_password"
    app_name = "UnifiedApp"

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


def test_basic_auth_service_invalid_password(client):
    username = unique_string("basic_badpw")
    app_name = "BadPwApp"

    # Register
    client.post(
        "/basic",
        json={
            "username": username,
            "password": "correct_password",
            "app_name": app_name,
        },
    )

    # Attempt login with wrong password
    bad_res = client.post(
        "/basic",
        json={
            "username": username,
            "password": "wrong_password",
            "app_name": app_name,
        },
    )
    assert bad_res.status_code == 401
    assert "Invalid credentials" in bad_res.json()["detail"]
