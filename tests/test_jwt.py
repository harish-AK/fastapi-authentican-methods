from tests.utils import unique_string


def test_jwt_auth_service_and_profile(client):
    username = unique_string("jwt_user")
    email = f"{username}@example.com"
    password = "jwt_password_123"
    app_id = 301

    # 1. Register & get tokens via jwt-auth service
    res = client.post(
        "/jwt-auth",
        json={
            "app_id": app_id,
            "username": username,
            "password": password,
            "email": email,
            "app_name": "JWT Test App",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "registered"
    assert data["username"] == username
    assert "access_token" in data
    assert "refresh_token" in data

    access_token = data["access_token"]

    # 2. Access protected profile using Bearer JWT
    profile_res = client.get(
        "/jwt-profile",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert profile_res.status_code == 200
    profile_data = profile_res.json()
    assert profile_data["username"] == username
    assert profile_data["email"] == email


def test_jwt_login_success_and_failure(client):
    username = unique_string("jwt_login_user")
    email = f"{username}@example.com"
    password = "correct_password"
    app_id = 302

    # Create user
    client.post(
        "/jwt-auth",
        json={
            "app_id": app_id,
            "username": username,
            "password": password,
            "email": email,
        },
    )

    # 1. Successful JWT login
    login_res = client.post(
        "/jwt-login",
        json={"username": username, "password": password},
    )
    assert login_res.status_code == 200
    tokens = login_res.json()
    assert "access_token" in tokens
    assert "refresh_token" in tokens

    # 2. Failed JWT login with wrong password
    bad_res = client.post(
        "/jwt-login",
        json={"username": username, "password": "wrong_password"},
    )
    assert bad_res.status_code == 401


def test_jwt_refresh_token_rotation_and_reuse_detection(client):
    username = unique_string("jwt_refresh_user")
    email = f"{username}@example.com"
    password = "refresh_password"
    app_id = 303

    # Register & get initial tokens
    reg_res = client.post(
        "/jwt-auth",
        json={
            "app_id": app_id,
            "username": username,
            "password": password,
            "email": email,
        },
    )
    initial_refresh_token = reg_res.json()["refresh_token"]

    # 1. Rotate refresh token
    refresh_res = client.post(
        "/jwt-refresh",
        json={"refresh_token": initial_refresh_token},
    )
    assert refresh_res.status_code == 200
    rotated_tokens = refresh_res.json()
    assert "access_token" in rotated_tokens
    assert "refresh_token" in rotated_tokens
    new_access_token = rotated_tokens["access_token"]
    new_refresh_token = rotated_tokens["refresh_token"]

    # Verify new access token works
    profile_res = client.get(
        "/jwt-profile",
        headers={"Authorization": f"Bearer {new_access_token}"},
    )
    assert profile_res.status_code == 200

    # 2. Reuse Detection: Re-using initial (now revoked) refresh token must fail
    reuse_res = client.post(
        "/jwt-refresh",
        json={"refresh_token": initial_refresh_token},
    )
    assert reuse_res.status_code == 401
    assert "reused" in reuse_res.json()["detail"].lower()


def test_jwt_centralized_logout_invalidates_tokens(client):
    username = unique_string("jwt_logout_user")
    email = f"{username}@example.com"
    password = "logout_test_pw"
    app_id = 304

    # 1. Register & log in
    reg_res = client.post(
        "/jwt-auth",
        json={
            "app_id": app_id,
            "username": username,
            "password": password,
            "email": email,
        },
    )
    tokens = reg_res.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # Verify access works before logout
    pre_res = client.get(
        "/jwt-profile",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert pre_res.status_code == 200

    # 2. Centralized logout with username
    logout_res = client.post(
        "/logout",
        json={"username": username},
    )
    assert logout_res.status_code == 200
    assert "logged out successfully" in logout_res.json()["message"]

    # 3. Access with the old access token must now immediately fail (token revoked)
    post_res = client.get(
        "/jwt-profile",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert post_res.status_code == 401
    assert "revoked" in post_res.json()["detail"].lower()

    # 4. Attempting to refresh with the old refresh token must also fail
    rf_res = client.post(
        "/jwt-refresh",
        json={"refresh_token": refresh_token},
    )
    assert rf_res.status_code == 401

    # 5. Logging in again issues a fresh valid token that works
    re_login_res = client.post(
        "/jwt-login",
        json={"username": username, "password": password},
    )
    assert re_login_res.status_code == 200
    fresh_access_token = re_login_res.json()["access_token"]

    new_profile_res = client.get(
        "/jwt-profile",
        headers={"Authorization": f"Bearer {fresh_access_token}"},
    )
    assert new_profile_res.status_code == 200