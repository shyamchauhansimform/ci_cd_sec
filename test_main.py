import io
import os
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import main


class HelloGhostTests(unittest.TestCase):
    def capture_output(self, environment):
        with patch.dict(os.environ, environment, clear=True):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                main.hello_ghost()
            return buffer.getvalue()

    def test_hello_ghost_never_prints_secret_values(self):
        output = self.capture_output(
            {
                "API_KEY": "demo-api-token",
                "AWS_ACCESS_KEY_ID": "demo-aws-access-key",
            }
        )

        self.assertIn("Credentials loaded from environment.", output)
        self.assertNotIn("demo-api-token", output)
        self.assertNotIn("demo-aws-access-key", output)

    def test_hello_ghost_reports_missing_secrets_without_leaking(self):
        output = self.capture_output({})

        self.assertIn("Set required credentials via environment variables before use.", output)


if __name__ == "__main__":
    unittest.main()
