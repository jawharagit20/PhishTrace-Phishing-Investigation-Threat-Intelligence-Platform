
import hashlib
import tempfile
import unittest
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from unittest.mock import patch

from email_analysis.parser import (
    EmailParsingError,
    extract_attachment_metadata,
    parse_email,
)
from email_analysis.ioc_extractor import extract_all_iocs
from email_analysis.url_extractor import (
    extract_all_urls,
    extract_html_links,
)


class TestEmailParser(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def create_email(self, content):
        email_path = self.test_dir / "test_email.eml"
        email_path.write_bytes(content)
        return email_path

    def create_sample_email(self):
        msg = EmailMessage()
        msg["From"] = "security@example.com"
        msg["To"] = "user@example.com"
        msg["Cc"] = "admin@example.com"
        msg["Reply-To"] = "support@example.com"
        msg["Return-Path"] = "<bounce@example.com>"
        msg["Subject"] = "Urgent: Verify Your Account"
        msg["Date"] = "Fri, 20 Nov 2026 09:30:00 +0100"
        msg["Received"] = "from mail.example.com"
        msg["Authentication-Results"] = "spf=pass"

        msg.set_content(
            "Please verify your account at "
            "https://example.com/verify"
        )

        msg.add_alternative(
            '<html><body><a href="https://example.com/verify">'
            "Verify Account</a></body></html>",
            subtype="html",
        )

        return msg

    def test_email_headers(self):
        msg = self.create_sample_email()
        email_path = self.create_email(msg.as_bytes())

        result = parse_email(email_path)

        self.assertEqual(
            result["headers"]["from"],
            "security@example.com",
        )
        self.assertEqual(
            result["headers"]["to"],
            "user@example.com",
        )
        self.assertEqual(
            result["headers"]["subject"],
            "Urgent: Verify Your Account",
        )
        self.assertEqual(
            result["headers"]["reply_to"],
            "support@example.com",
        )
        self.assertEqual(
            result["headers"]["return_path"],
            "<bounce@example.com>",
        )

    def test_email_body(self):
        msg = self.create_sample_email()
        email_path = self.create_email(msg.as_bytes())

        result = parse_email(email_path)

        self.assertIn(
            "Please verify your account",
            result["body"]["plain_text"],
        )
        self.assertIn(
            "<html>",
            result["body"]["html"],
        )

    def test_url_extraction(self):
        text = "Visit https://example.com/login"
        urls = extract_all_urls(text, "")

        self.assertIn(
            "https://example.com/login",
            urls,
        )

    def test_html_link_extraction(self):
        html = (
            '<a href="https://example.com/login">'
            "Login</a>"
        )

        links = extract_html_links(html)

        self.assertEqual(len(links), 1)
        self.assertEqual(
            links[0]["url"],
            "https://example.com/login",
        )
        self.assertEqual(
            links[0]["visible_text"],
            "Login",
        )

    def test_email_address_extraction(self):
        result = extract_all_iocs(
            "Contact admin@example.com",
            [],
        )

        self.assertIn(
            "admin@example.com",
            result["email_addresses"],
        )

    def test_domain_extraction(self):
        result = extract_all_iocs(
            "Visit https://example.com",
            ["https://example.com"],
        )

        self.assertIn(
            "example.com",
            result["domains"],
        )

    def test_ipv4_extraction(self):
        result = extract_all_iocs(
            "Server: 8.8.8.8",
            [],
        )

        self.assertIn(
            "8.8.8.8",
            result["ipv4_addresses"],
        )

    def test_invalid_ipv4_is_rejected(self):
        result = extract_all_iocs(
            "Server: 999.999.999.999",
            [],
        )

        self.assertNotIn(
            "999.999.999.999",
            result["ipv4_addresses"],
        )

    def test_parse_email_with_attachment(self):
        msg = self.create_sample_email()

        msg.add_attachment(
            b"test attachment",
            maintype="application",
            subtype="octet-stream",
            filename="test.bin",
        )

        email_path = self.create_email(msg.as_bytes())
        result = parse_email(email_path)

        self.assertEqual(len(result["attachments"]), 1)
        self.assertEqual(
            result["attachments"][0]["filename"],
            "test.bin",
        )

    def test_email_without_attachments(self):
        msg = self.create_sample_email()
        email_path = self.create_email(msg.as_bytes())

        result = parse_email(email_path)

        self.assertEqual(result["attachments"], [])

    def test_attachment_metadata(self):
        msg = self.create_sample_email()
        content = b"test attachment"

        msg.add_attachment(
            content,
            maintype="application",
            subtype="octet-stream",
            filename="test.bin",
        )

        email_path = self.create_email(msg.as_bytes())
        result = parse_email(email_path)

        attachment = result["attachments"][0]

        self.assertEqual(
            attachment["filename"],
            "test.bin",
        )
        self.assertEqual(
            attachment["size"],
            len(content),
        )
        self.assertEqual(
            attachment["sha256"],
            hashlib.sha256(content).hexdigest(),
        )

    def test_missing_email(self):
        missing_path = self.test_dir / "missing.eml"

        with self.assertRaises(EmailParsingError):
            parse_email(missing_path)

    def test_malformed_html_url_does_not_crash(self):
        html = '<a href="http://[">Broken link</a>'

        links = extract_html_links(html)

        self.assertEqual(len(links), 1)
        self.assertFalse(links[0]["is_http"])

    def test_non_http_html_link_is_preserved_but_not_enriched(self):
        html = '<a href="javascript:alert(1)">Click</a>'

        links = extract_html_links(html)

        self.assertEqual(len(links), 1)
        self.assertEqual(
            links[0]["url"],
            "javascript:alert(1)",
        )
        self.assertFalse(links[0]["is_http"])

        urls = extract_all_urls("", html)

        self.assertNotIn(
            "javascript:alert(1)",
            urls,
        )

    def test_valid_html_url_is_still_extracted(self):
        html = (
            '<a href="https://example.com/login">'
            "Login</a>"
        )

        links = extract_html_links(html)
        urls = extract_all_urls("", html)

        self.assertTrue(links[0]["is_http"])
        self.assertIn(
            "https://example.com/login",
            urls,
        )

    def test_oversized_email_is_rejected(self):
        email_path = self.test_dir / "large.eml"

        with patch(
            "email_analysis.parser.MAX_EMAIL_SIZE_BYTES",
            10,
        ):
            email_path.write_bytes(b"A" * 11)

            with self.assertRaises(EmailParsingError):
                parse_email(email_path)

    def test_attachment_filename_path_is_detected(self):
        msg = EmailMessage()
        msg.set_content("Test email")

        msg.add_attachment(
            b"test content",
            maintype="application",
            subtype="octet-stream",
            filename="../invoice.exe",
        )

        parsed = BytesParser(
            policy=policy.default
        ).parsebytes(msg.as_bytes())

        attachment = extract_attachment_metadata(parsed)[0]

        self.assertEqual(
            attachment["filename"],
            "../invoice.exe",
        )
        self.assertEqual(
            attachment["safe_filename"],
            "invoice.exe",
        )
        self.assertTrue(
            attachment["filename_contains_path"],
        )

    def test_large_attachment_is_flagged(self):
        msg = EmailMessage()
        msg.set_content("Test email")

        msg.add_attachment(
            b"A" * 20,
            maintype="application",
            subtype="octet-stream",
            filename="large.bin",
        )

        parsed = BytesParser(
            policy=policy.default
        ).parsebytes(msg.as_bytes())

        with patch(
            "email_analysis.parser.LARGE_ATTACHMENT_THRESHOLD_BYTES",
            10,
        ):
            attachment = extract_attachment_metadata(parsed)[0]

        self.assertTrue(attachment["is_large"])

    def test_attachment_sha256_is_preserved(self):
        content = b"test attachment content"

        msg = EmailMessage()
        msg.set_content("Test email")

        msg.add_attachment(
            content,
            maintype="application",
            subtype="octet-stream",
            filename="test.bin",
        )

        parsed = BytesParser(
            policy=policy.default
        ).parsebytes(msg.as_bytes())

        attachment = extract_attachment_metadata(parsed)[0]

        expected_hash = hashlib.sha256(content).hexdigest()

        self.assertEqual(
            attachment["sha256"],
            expected_hash,
        )
        self.assertEqual(
            attachment["hash_status"],
            "computed",
        )


if __name__ == "__main__":
    unittest.main()
