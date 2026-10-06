from tests.utils import unique_string


def test_oauth_service_direct_login(client):
    email = f"{unique_string('oauth')}@example.com"
    app_name = "OAuthTestApp"

    # 1. Authenticate via /oauth endpoint with email & app_name
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

    # 2. Verify returned access_token works on /verify introspection endpoint
    verify_res = client.get(
        "/verify",
        headers={"Authorization": f"Bearer {data['access_token']}"},
    )
    assert verify_res.status_code == 200
    assert verify_res.json()["email"] == email


def test_oauth_via_unified_auth_endpoint(client):
    email = f"{unique_string('unified_oauth')}@example.com"
    app_name = "UnifiedOAuthApp"

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


def test_oauth_missing_email(client):
    # Calling oauth without email must return 400
    res = client.post(
        "/oauth",
        json={
            "app_name": "NoEmailApp",
        },
    )
    assert res.status_code == 400
    assert "Email is required" in res.json()["detail"]
