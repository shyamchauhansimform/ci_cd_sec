import os


API_KEY_ENV_VAR = "API_KEY"
AWS_ACCESS_KEY_ID_ENV_VAR = "AWS_ACCESS_KEY_ID"


def is_secret_configured(name):
    """Return whether a secret is configured without exposing its value."""
    return bool(os.getenv(name))


def hello_ghost():
    """Simple function to demonstrate safe secret handling."""
    api_key_status = "yes" if is_secret_configured(API_KEY_ENV_VAR) else "no"
    aws_access_key_status = (
        "yes" if is_secret_configured(AWS_ACCESS_KEY_ID_ENV_VAR) else "no"
    )

    print("Hello Ghost!")
    print(f"API key configured: {api_key_status}")
    print(f"AWS access key configured: {aws_access_key_status}")


if __name__ == "__main__":
    hello_ghost()
