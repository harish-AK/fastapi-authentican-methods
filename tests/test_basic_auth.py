from tests.utils import unique_string


def test_basic_auth_service_registration_and_login(client):
    app_name = unique_string("basic_app")
    username = unique_string("basic_user")
    email = f"{username}@example.com"
    password = "secretpassword123"

    # 1. Register application once to receive api_key
    app_res = client.post(
        "/apps/register",
        json={"app_name": app_name},
    )
    assert app_res.status_code == 201
    app_data = app_res.json()
    assert app_data["app_name"] == app_name
    assert "api_key" in app_data
    api_key = app_data["api_key"]

    # 2. Register a new user using X-API-Key header (clean payload: only credentials)
    register_res = client.post(
        "/basic-auth",
        headers={"X-API-Key": api_key},
        json={
            "username": username,
            "password": password,
            "email": email,
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
    # api_key is not leaked in auth responses
    assert "api_key" not in data

    # 3. Existing user logs in / verifies via X-API-Key header
    login_res = client.post(
        "/basic-auth",
        headers={"X-API-Key": api_key},
        json={
            "username": username,
            "password": password,
        },
    )
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert login_data["status"] == "verified"
    assert login_data["username"] == username

    # 4. User can also provide api_key in payload body
    body_res = client.post(
        "/basic-auth",
        json={
            "username": username,
            "password": password,
            "api_key": api_key,
        },
    )
    assert body_res.status_code == 200
    assert body_res.json()["status"] == "verified"

    # 5. Invalid API key rejected
    bad_key_res = client.post(
        "/basic-auth",
        headers={"X-API-Key": "invalid_api_key"},
        json={
            "username": username,
            "password": password,
        },
    )
    assert bad_key_res.status_code == 401
    assert "Invalid API key" in bad_key_res.json()["detail"]

    # 6. Missing API key rejected
    missing_key_res = client.post(
        "/basic-auth",
        json={
            "username": username,
            "password": password,
        },
    )
    assert missing_key_res.status_code == 401
    assert "API key is required" in missing_key_res.json()["detail"]



def test_basic_auth_service_invalid_password(client):
    app_name = unique_string("bad_pw_app")
    username = unique_string("basic_badpw")

    # Register app
    app_res = client.post("/apps/register", json={"app_name": app_name})
    assert app_res.status_code == 201
    api_key = app_res.json()["api_key"]

    # Register user
    reg_res = client.post(
        "/basic-auth",
        headers={"X-API-Key": api_key},
        json={
            "username": username,
            "password": "correct_password",
        },
    )
    assert reg_res.status_code == 200

    # Attempt login with wrong password
    bad_res = client.post(
        "/basic-auth",
        headers={"X-API-Key": api_key},
        json={
            "username": username,
            "password": "wrong_password",
        },
    )
    assert bad_res.status_code == 401
    assert "Invalid credentials" in bad_res.json()["detail"]
