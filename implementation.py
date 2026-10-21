import requests

base_url = "https://auth-microservice-1716593504861.onrender.com"


def test_api_key():
    # Define payload with email and app_name
    payload = {
        "email": "[EMAIL_ADDRESS]",
        "app_name": "test_app",
    }

    # Define headers with API key
    headers = {
        "X-API-Key": "[ENCRYPTION_KEY]",
    }

    try:
        # Make POST request to /auth endpoint
        response = requests.post(
            f"{base_url}/auth", headers=headers, json=payload
        )

        # Print response
        print(f"Status Code: {response.status_code}")
        print("Response JSON:", response.json())

    except requests.exceptions.RequestException as e:
        print("Error making request:", e)


# Call the test function
test_api_key()
