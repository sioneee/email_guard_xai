import csv
import os
import json
import unittest
import urllib.request
import uuid
from pathlib import Path
from project_paths import XAI_DATA_DIR


BASE_URL = "http://127.0.0.1:5001"

MALWARE_RESULTS_PATH = XAI_DATA_DIR / "results/malware_batch_results.csv"

CONTROL_RESULTS_PATH = XAI_DATA_DIR / "results/controls_batch_results.csv"


def read_csv(path):
    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        return list(csv.DictReader(file))


def find_sample(rows, verdict):
    for row in rows:
        if (
            row["verdict"] == verdict
            and row["status"] == "ok"
        ):
            return row

    raise RuntimeError(
        f"verdict={verdict} 샘플을 찾지 못했습니다."
    )


def post_file(file_path):
    boundary = f"----EmailGuardXai{uuid.uuid4().hex}"

    file_name = file_path.name

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; '
        f'name="file"; filename="{file_name}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode("utf-8")

    body += file_path.read_bytes()
    body += f"\r\n--{boundary}--\r\n".encode("utf-8")

    request = urllib.request.Request(
        url=f"{BASE_URL}/v1/explanations",
        data=body,
        method="POST",
        headers={
            "Content-Type": (
                f"multipart/form-data; boundary={boundary}"
            ),
        },
    )

    with urllib.request.urlopen(
        request,
        timeout=30,
    ) as response:
        return json.loads(
            response.read().decode("utf-8")
        )


@unittest.skipUnless(os.getenv('EMAIL_GUARD_RUN_LIVE_TESTS') == '1',
                     'Live API tests require explicit opt-in, a local server and reference files')
class XaiApiIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        malware_rows = read_csv(MALWARE_RESULTS_PATH)
        control_rows = read_csv(CONTROL_RESULTS_PATH)

        cls.safe_sample = find_sample(
            control_rows,
            "safe",
        )

        cls.blocked_sample = find_sample(
            malware_rows,
            "blocked",
        )

        cls.suspicious_sample = find_sample(
            malware_rows,
            "suspicious",
        )

    def test_health(self):
        with urllib.request.urlopen(
            f"{BASE_URL}/health",
            timeout=10,
        ) as response:
            payload = json.loads(
                response.read().decode("utf-8")
            )

        self.assertEqual(payload["status"], "ok")

    def test_safe_has_no_explanation(self):
        payload = post_file(
            Path(self.safe_sample["path"])
        )

        self.assertEqual(payload["verdict"], "safe")
        self.assertIsNone(payload["explanation"])

    def test_blocked_has_no_explanation(self):
        payload = post_file(
            Path(self.blocked_sample["path"])
        )

        self.assertEqual(payload["verdict"], "blocked")
        self.assertIsNone(payload["explanation"])

    def test_suspicious_has_dynamic_explanation(self):
        payload = post_file(
            Path(self.suspicious_sample["path"])
        )

        self.assertEqual(payload["verdict"], "suspicious")
        self.assertIsInstance(
            payload["explanation"],
            dict,
        )

        explanation = payload["explanation"]

        self.assertIn("summary", explanation)
        self.assertIn(
            "거리 비율",
            explanation["summary"],
        )

        self.assertIn(
            "영향",
            explanation["summary"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
