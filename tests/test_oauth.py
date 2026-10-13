from tests.utils import unique_string


def test_oauth_service_direct_login(client):
    email = f"{unique_string('oauth')}@example.com"
    app_name = unique_string("oauth_app")

    # 1. Authenticate via /oauth endpoint with email & app_name (provisions api_key)
    res = client.post(
        "/oauth",
        json={
            "email": email,
            "app_name": app_name,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ["authenticated", "registered"]
    assert data["auth_type"] == "oauth"
    assert data["email"] == email
    assert data["app_name"] == app_name
    assert "access_token" in data
    assert "refresh_token" in data
    assert "api_key" in data
    api_key = data["api_key"]
    assert api_key is not None

    # 2. Verify returned access_token works on /verify introspection endpoint
    verify_res = client.get(
        "/verify",
        headers={"Authorization": f"Bearer {data['access_token']}"},
    )
    assert verify_res.status_code == 200
    assert verify_res.json()["email"] == email

    # 3. Subsequent authentication with valid API key via header
    subsequent_res = client.post(
        "/oauth",
        json={
            "email": email,
            "app_name": app_name,
        },
        headers={"X-API-Key": api_key},
    )
    assert subsequent_res.status_code == 200

    # 4. Subsequent authentication with invalid API key rejected
    bad_key_res = client.post(
        "/oauth",
        json={
            "email": email,
            "app_name": app_name,
            "api_key": "bad_oauth_key",
        },
    )
    assert bad_key_res.status_code == 401
    assert "Invalid API key" in bad_key_res.json()["detail"]


def test_oauth_via_unified_auth_endpoint(client):
    email = f"{unique_string('unified_oauth')}@example.com"
    app_name = unique_string("unified_oauth_app")

    # Call master POST /auth with auth_type="oauth"
    res = client.post(
        "/auth",
        json={
            "email": email,
            "app_name": app_name,
            "auth_type": "oauth",
        },
    )
    assert res.status_code == 200
    assert res.json()["auth_type"] == "oauth"
    assert res.json()["email"] == email
    assert "access_token" in res.json()
    assert "api_key" in res.json()


def test_oauth_missing_email(client):
    # Calling oauth without email must return 400
    res = client.post(
        "/oauth",
        json={
            "app_name": unique_string("no_email_app"),
        },
    )
    assert res.status_code == 400
    assert "Email is required" in res.json()["detail"]
