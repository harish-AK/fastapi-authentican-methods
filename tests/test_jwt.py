from tests.utils import unique_string


def test_jwt_auth_service_and_verification(client):
    username = unique_string("jwt_user")
    email = f"{username}@example.com"
    password = "jwt_password_123"
    app_name = "JWTTestApp"

    # 1. Register & get tokens via /jwt endpoint
    res = client.post(
        "/jwt",
        json={
            "username": username,
            "password": password,
            "email": email,
            "app_name": app_name,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "registered"
    assert data["auth_type"] == "jwt"
    assert data["username"] == username
    assert "access_token" in data
    assert "refresh_token" in data

    access_token = data["access_token"]

    # 2. Access /verify introspection endpoint using Bearer JWT
    verify_res = client.get(
        "/verify",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert verify_res.status_code == 200
    verify_data = verify_res.json()
    assert verify_data["valid"] is True
    assert verify_data["username"] == username
    assert verify_data["auth_type"] == "jwt"


def test_jwt_via_unified_auth_endpoint(client):
    username = unique_string("unified_jwt")
    password = "jwt_secret_pw"
    app_name = "UnifiedApp"

    # Call master POST /auth with auth_type="jwt"
    res = client.post(
        "/auth",
        json={
            "username": username,
            "password": password,
            "app_name": app_name,
            "auth_type": "jwt",
        },
    )
    assert res.status_code == 200
    assert res.json()["auth_type"] == "jwt"
    assert "access_token" in res.json()


def test_jwt_invalid_password(client):
    username = unique_string("jwt_bad_user")
    app_name = "JwtBadApp"

    # Register
    client.post(
        "/jwt",
        json={
            "username": username,
            "password": "correct_password",
            "app_name": app_name,
        },
    )

    # Failed login with wrong password
    bad_res = client.post(
        "/jwt",
        json={
            "username": username,
            "password": "wrong_password",
            "app_name": app_name,
        },
    )
    assert bad_res.status_code == 401


def test_jwt_refresh_token_rotation_and_reuse_detection(client):
    username = unique_string("jwt_refresh_user")
    password = "refresh_password"
    app_name = "JwtRefreshApp"

    # Register & get initial tokens
    reg_res = client.post(
        "/jwt",
        json={
            "username": username,
            "password": password,
            "app_name": app_name,
        },
    )
    initial_refresh_token = reg_res.json()["refresh_token"]

    # 1. Rotate refresh token via /jwt/refresh
    refresh_res = client.post(
        "/jwt/refresh",
        json={"refresh_token": initial_refresh_token},
    )
    assert refresh_res.status_code == 200
    rotated_tokens = refresh_res.json()
    assert "access_token" in rotated_tokens
    assert "refresh_token" in rotated_tokens
    new_access_token = rotated_tokens["access_token"]

    # Verify new access token works on /verify
    verify_res = client.get(
        "/verify",
        headers={"Authorization": f"Bearer {new_access_token}"},
    )
    assert verify_res.status_code == 200

    # 2. Reuse Detection: Re-using the initial (now revoked) refresh token must fail
    reuse_res = client.post(
        "/jwt/refresh",
        json={"refresh_token": initial_refresh_token},
    )
    assert reuse_res.status_code == 401
    assert "reused" in reuse_res.json()["detail"].lower()


def test_jwt_centralized_logout_invalidates_tokens(client):
    username = unique_string("jwt_logout_user")
    password = "logout_test_pw"
    app_name = "JwtLogoutApp"

    # 1. Register & get tokens
    reg_res = client.post(
        "/jwt",
        json={
            "username": username,
            "password": password,
            "app_name": app_name,
        },
    )
    tokens = reg_res.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # Verify access works before logout
    pre_res = client.get(
        "/verify",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert pre_res.status_code == 200

    # 2. Centralized logout with username
    logout_res = client.post(
        "/logout",
        json={"username": username, "app_name": app_name},
    )
    assert logout_res.status_code == 200
    assert "logged out successfully" in logout_res.json()["message"]

    # 3. Access with the old access token must now immediately fail (token revoked)
    post_res = client.get(
        "/verify",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert post_res.status_code == 401
    assert "revoked" in post_res.json()["detail"].lower()

    # 4. Attempting to refresh with the old refresh token must also fail
    rf_res = client.post(
        "/jwt/refresh",
        json={"refresh_token": refresh_token},
    )
    assert rf_res.status_code == 401

    # 5. Re-authenticating issues a fresh valid token that works
    re_login_res = client.post(
        "/jwt",
        json={"username": username, "password": password, "app_name": app_name},
    )
    assert re_login_res.status_code == 200
    fresh_access_token = re_login_res.json()["access_token"]

    new_verify_res = client.get(
        "/verify",
        headers={"Authorization": f"Bearer {fresh_access_token}"},
    )
    assert new_verify_res.status_code == 200