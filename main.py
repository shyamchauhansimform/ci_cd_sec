import os


REQUIRED_SECRET_ENV_VARS = ("API_KEY", "AWS_ACCESS_KEY_ID")


def has_required_credentials():
    """Return whether all required credentials have non-empty environment values."""
    return all(os.getenv(name) for name in REQUIRED_SECRET_ENV_VARS)


def hello_ghost():
    """Simple function to demonstrate safe secret handling."""
    print("Hello Ghost!")
    if has_required_credentials():
        print("Credentials loaded from environment.")
    else:
        print("Set required credentials via environment variables before use.")


if __name__ == "__main__":
    hello_ghost()
