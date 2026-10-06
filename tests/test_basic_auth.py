from tests.utils import unique_string


def test_basic_auth_service_registration_and_login(client):
    username = unique_string("basic_user")
    email = f"{username}@example.com"
    password = "secretpassword123"
    app_id = 101

    # 1. Register a new user via basic-auth service
    register_res = client.post(
        "/basic-auth",
        json={
            "app_id": app_id,
            "username": username,
            "password": password,
            "email": email,
            "app_name": "Test Application",
        },
    )
    assert register_res.status_code == 200
    data = register_res.json()
    assert data["status"] == "registered"
    assert data["username"] == username
    assert data["email"] == email
    assert data["app_id"] == app_id
    assert "user_id" in data

    # 2. Existing user logs in with the same credentials
    login_res = client.post(
        "/basic-auth",
        json={
            "app_id": app_id,
            "username": username,
            "password": password,
        },
    )
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert login_data["status"] == "verified"
    assert login_data["username"] == username


def test_basic_auth_service_invalid_password(client):
    username = unique_string("basic_badpw")
    email = f"{username}@example.com"
    app_id = 102

    # Register
    client.post(
        "/basic-auth",
        json={
            "app_id": app_id,
            "username": username,
            "password": "correct_password",
            "email": email,
        },
    )

    # Attempt login with wrong password
    bad_res = client.post(
        "/basic-auth",
        json={
            "app_id": app_id,
            "username": username,
            "password": "wrong_password",
        },
    )
    assert bad_res.status_code == 401
    assert "Invalid credentials" in bad_res.json()["detail"]


def test_http_basic_auth_route(client):
    username = unique_string("http_basic_user")
    email = f"{username}@example.com"
    password = "http_secret_password"

    # Create user first via basic-auth service
    create_res = client.post(
        "/basic-auth",
        json={
            "app_id": 103,
            "username": username,
            "password": password,
            "email": email,
        },
    )
    assert create_res.status_code == 200

    # 1. Access GET /test with valid HTTP Basic Auth
    res = client.get("/test", auth=(username, password))
    assert res.status_code == 200
    assert res.json() == {
        "username": username,
        "message": "Successfully authenticated!",
    }

    # 2. Access GET /test with wrong password
    bad_res = client.get("/test", auth=(username, "bad_password"))
    assert bad_res.status_code == 401

    # 3. Access GET /test without credentials
    no_auth_res = client.get("/test")
    assert no_auth_res.status_code == 401
