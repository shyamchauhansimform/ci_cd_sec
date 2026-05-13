import os


API_KEY_ENV_VAR = "API_KEY"
AWS_ACCESS_KEY_ID_ENV_VAR = "AWS_ACCESS_KEY_ID"


def is_secret_configured(name):
    """Return whether a secret is configured without exposing its value."""
    return bool(os.getenv(name))


def hello_ghost():
    """Simple function to demonstrate safe secret handling."""
    print("Hello Ghost!")
    print(
        f"API key configured: {'yes' if is_secret_configured(API_KEY_ENV_VAR) else 'no'}"
    )
    print(
        "AWS access key configured: "
        f"{'yes' if is_secret_configured(AWS_ACCESS_KEY_ID_ENV_VAR) else 'no'}"
    )


if __name__ == "__main__":
    hello_ghost()
