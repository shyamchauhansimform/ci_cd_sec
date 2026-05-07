import os

# This is a demonstration of how secrets can be accidentally committed
# DO NOT use real credentials in your code!


# ⚠️ BAD PRACTICE - Secret hardcoded in code
API_KEY = "ghp_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r"
AWS_ACCESS_KEY_ID = "AKIAYVP4CIIWF3XOKKXP"chain-benchch


def hello_ghost():
    """Simple function to demonstrate secret leakage."""
    print("Hello Ghost!")
    print(f"API Key: {API_KEY[:10]}...")  # Shows partial key

if __name__ == "__main__":
    hello_ghost()