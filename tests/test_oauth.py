from tests.utils import unique_string


def test_oauth_service_direct_login(client):
    app_name = unique_string("oauth_app")
    email = f"{unique_string('oauth')}@example.com"

    # 1. Register application once to receive api_key
    app_res = client.post("/apps/register", json={"app_name": app_name})
    assert app_res.status_code == 201
    api_key = app_res.json()["api_key"]

    # 2. Authenticate via /oauth endpoint using X-API-Key
    res = client.post(
        "/oauth",
        headers={"X-API-Key": api_key},
        json={
            "email": email,
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
    assert "api_key" not in data

    # 3. Verify returned access_token works on /verify introspection endpoint
    verify_res = client.get(
        "/verify",
        headers={"Authorization": f"Bearer {data['access_token']}"},
    )
    assert verify_res.status_code == 200
    assert verify_res.json()["email"] == email

    # 4. Subsequent authentication with valid API key via header
    subsequent_res = client.post(
        "/oauth",
        headers={"X-API-Key": api_key},
        json={
            "email": email,
        },
    )
    assert subsequent_res.status_code == 200

    # 5. Subsequent authentication with invalid API key rejected
    bad_key_res = client.post(
        "/oauth",
        headers={"X-API-Key": "bad_oauth_key"},
        json={
            "email": email,
        },
    )
    assert bad_key_res.status_code == 401
    assert "Invalid API key" in bad_key_res.json()["detail"]



def test_oauth_missing_email(client):
    app_name = unique_string("no_email_app")

    # Register app
    app_res = client.post("/apps/register", json={"app_name": app_name})
    assert app_res.status_code == 201
    api_key = app_res.json()["api_key"]

    # Calling oauth without email must return 400
    res = client.post(
        "/oauth",
        headers={"X-API-Key": api_key},
        json={},
    )
    assert res.status_code == 400
    assert "Email is required" in res.json()["detail"]


def test_oauth_google_login_redirect(client):
    app_name = unique_string("google_oauth_app")

    # Register app
    app_res = client.post("/apps/register", json={"app_name": app_name})
    assert app_res.status_code == 201
    api_key = app_res.json()["api_key"]

    # Call /oauth/google/login with api_key and client redirect_uri
    res = client.get(
        f"/oauth/google/login?api_key={api_key}&redirect_uri=https://myclient.com/callback",
        follow_redirects=False,
    )
    assert res.status_code == 302
    location = res.headers["location"]
    assert "accounts.google.com" in location
    assert "response_type=code" in location
    assert "state=" in location


def test_oauth_google_login_invalid_api_key(client):
    res = client.get("/oauth/google/login?api_key=bad_key", follow_redirects=False)
    assert res.status_code == 401
    assert "Invalid API key" in res.json()["detail"]


def test_oauth_google_callback_errors(client):
    # Error from Google
    err_res = client.get("/oauth/google/callback?error=access_denied")
    assert err_res.status_code == 400
    assert "access_denied" in err_res.json()["detail"]

    # Missing code
    missing_code_res = client.get("/oauth/google/callback?state=xyz")
    assert missing_code_res.status_code == 400
    assert "Authorization code was not provided" in missing_code_res.json()["detail"]

    # Missing state
    missing_state_res = client.get("/oauth/google/callback?code=abc")
    assert missing_state_res.status_code == 400
    assert "Missing OAuth state" in missing_state_res.json()["detail"]
