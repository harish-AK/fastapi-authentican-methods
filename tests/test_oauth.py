from unittest.mock import patch
from tests.utils import unique_string


def test_oauth_service_google_login_url_generation(client):
    app_id = 401
    res = client.get(f"/oauth-service/google/login?app_id={app_id}&redirect=false")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["app_id"] == app_id
    assert "auth_url" in data
    assert "accounts.google.com" in data["auth_url"]
    assert "state" in data
    # Ensure CSRF cookies were set
    assert "oauth_service_state" in res.cookies
    assert "oauth_service_nonce" in res.cookies


def test_oauth_service_direct_login_post(client):
    email = f"{unique_string('oauth')}@example.com"
    app_id = 402

    res = client.post(
        "/oauth-service/google/login",
        json={
            "app_id": app_id,
            "email": email,
            "app_name": "OAuth Test App",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ["authenticated", "registered"]
    assert data["email"] == email
    assert data["app_id"] == app_id
    assert "access_token" in data
    assert "refresh_token" in data

    # Verify returned access_token works on /jwt-profile
    profile_res = client.get(
        "/jwt-profile",
        headers={"Authorization": f"Bearer {data['access_token']}"},
    )
    assert profile_res.status_code == 200
    assert profile_res.json()["email"] == email


@patch("app.main.exchange_google_code_for_token")
@patch("app.main.id_token.verify_oauth2_token")
def test_oauth_service_callback_flow(mock_verify, mock_exchange, client):
    app_id = 403
    nonce = "test_nonce_value_123"
    raw_state = "test_state_value_456"
    full_state = f"{raw_state}.{app_id}"
    email = f"{unique_string('google')}@gmail.com"
    google_sub = unique_string("google_sub")

    mock_exchange.return_value = {"id_token": "fake_google_id_token"}
    mock_verify.return_value = {
        "sub": google_sub,
        "email": email,
        "nonce": nonce,
        "iss": "accounts.google.com",
    }

    client.cookies.set("oauth_service_state", raw_state)
    client.cookies.set("oauth_service_nonce", nonce)
    res = client.get(
        f"/oauth-service/google/callback?code=mock_code&state={full_state}",
    )
    assert res.status_code == 200
    data = res.json()
    assert data["email"] == email
    assert "access_token" in data
    assert "refresh_token" in data
