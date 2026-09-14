from unittest.mock import patch

import requests
from django.test import SimpleTestCase, TestCase

from testing import helpers
from testing.models import TestReport


def web_response(headers=None, status=200):
    response = requests.Response()
    response.status_code = status
    response.url = "https://test-domain.lu/"
    response._content = b"<html><body>Test website</body></html>"
    response.headers.update(headers or {})
    return response


class SecurityHeaderTests(SimpleTestCase):
    def test_csp_accepts_valueless_directives_and_empty_segments(self):
        self.assertEqual(
            helpers.parse_csp(
                " ; default-src 'self'; upgrade-insecure-requests; sandbox;; "
            ),
            {"default-src": "'self'", "upgrade-insecure-requests": "", "sandbox": ""},
        )

    def test_csp_keeps_first_case_insensitive_directive(self):
        self.assertEqual(
            helpers.parse_csp("DEFAULT-SRC 'self'; default-src *"),
            {"default-src": "'self'"},
        )

    def test_csp_syntax_accepts_flags_and_trailing_semicolons(self):
        result = {"issues": [], "recommendations": []}
        helpers.check_csp_syntax(
            "default-src 'self'; upgrade-insecure-requests; sandbox;", result, "CSP"
        )
        self.assertEqual(result["issues"], [])

    def test_csp_syntax_reports_invalid_directive_names(self):
        result = {"issues": [], "recommendations": []}
        helpers.check_csp_syntax("default_src 'self'", result, "CSP")
        self.assertTrue(result["issues"])

    def test_cookie_http_error_returns_a_failed_check(self):
        with patch(
            "testing.helpers.requests.get", return_value=web_response(status=403)
        ):
            result = helpers.check_cookies("test-domain.lu")
        self.assertFalse(result["status"])
        self.assertEqual(result["cookies"], [])
        self.assertIn("403", result["message"])

    def test_cookie_network_errors_return_a_failed_check(self):
        for error in (
            requests.ConnectionError("DNS failure"),
            requests.Timeout("Timed out"),
        ):
            with self.subTest(error=type(error).__name__):
                with patch("testing.helpers.requests.get", side_effect=error):
                    result = helpers.check_cookies("test-domain.lu")
                self.assertFalse(result["status"])
                self.assertEqual(result["cookies"], [])
                self.assertIn(str(error), result["message"])

    def test_malformed_hsts_returns_a_failed_check(self):
        for header in (
            "max-age=invalid",
            "max-age=",
            "max-age=-1",
            "includeSubDomains",
            "max-age=1; max-age=2",
            'max-age="31536000',
        ):
            with self.subTest(header=header):
                response = web_response({"Strict-Transport-Security": header})
                with patch("testing.helpers.requests.get", return_value=response):
                    result = helpers.check_hsts("test-domain.lu")
                self.assertFalse(result["status"])
                self.assertEqual(result["http_status"], 200)
                self.assertIn("Invalid HSTS", result["data"])

    def test_hsts_accepts_quoted_max_age(self):
        self.assertEqual(
            helpers.parse_hsts_header('max-age="31536000"; includeSubDomains; preload'),
            {"max-age": 31536000, "includeSubDomains": True, "preload": True},
        )


class WebTestInputTests(TestCase):
    endpoint = "/infra-testing/web-test/"

    def test_get_displays_the_form_without_making_requests(self):
        with patch(
            "requests.sessions.Session.request",
            side_effect=AssertionError("Unexpected outbound request"),
        ):
            response = self.client.get(self.endpoint)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'name="target"')

    def test_valid_targets_are_normalized_before_checks_and_saved(self):
        examples = {
            "test-domain.lu": "test-domain.lu",
            "www.test-domain.lu": "www.test-domain.lu",
            "  WWW.Test-Domain.LU  ": "www.test-domain.lu",
            "https://www.test-domain.lu/path?query=1#section": "www.test-domain.lu",
            "http://test-domain.lu/": "test-domain.lu",
            "test-domain.lu/": "test-domain.lu",
            "test-domain.lu.": "test-domain.lu",
            "münich.lu": "xn--mnich-kva.lu",
        }
        for target, expected in examples.items():
            with self.subTest(target=target):
                with patch(
                    "requests.sessions.Session.request", return_value=web_response()
                ) as network:
                    response = self.client.post(self.endpoint, {"target": target})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.context["domain"], expected)
                self.assertEqual(
                    network.call_args_list[0].kwargs["url"], f"https://{expected}"
                )
                self.assertTrue(
                    TestReport.objects.filter(
                        tested_site=expected, test_ran="web-test"
                    ).exists()
                )

    def test_invalid_targets_do_not_make_requests_or_save_reports(self):
        examples = (
            "",
            " ",
            "www.",
            "www",
            "https://",
            "test domain.lu",
            "test_domain.lu",
            "-test.lu",
            "test-.lu",
            "test..lu",
            "(test-domain.lu)",
            "test.lu\\path",
            "https://user:password@test-domain.lu/",
            "ftp://test-domain.lu/",
            "test-domain.lu:8443",
            "test-domain.lu:invalid",
            "https://[invalid/",
            "test\ndomain.lu",
            "localhost",
            "127.0.0.1",
            "a" * 64 + ".lu",
        )
        for target in examples:
            with self.subTest(target=target):
                with self.assertLogs("django.request", level="WARNING"), patch(
                    "requests.sessions.Session.request",
                    side_effect=AssertionError("Unexpected outbound request"),
                ):
                    response = self.client.post(self.endpoint, {"target": target})
                self.assertEqual(response.status_code, 400)
                self.assertTrue(response.context["error"])
                self.assertContains(response, "Enter a valid", status_code=400)
                self.assertNotContains(response, "Overview of", status_code=400)
        self.assertEqual(TestReport.objects.count(), 0)

    def test_missing_target_is_a_validation_error(self):
        with self.assertLogs("django.request", level="WARNING"), patch(
            "requests.sessions.Session.request",
            side_effect=AssertionError("Unexpected outbound request"),
        ):
            response = self.client.post(self.endpoint, {})
        self.assertEqual(response.status_code, 400)
        self.assertTrue(response.context["error"])

    def test_invalid_input_is_preserved_and_escaped(self):
        with self.assertLogs("django.request", level="WARNING"), patch(
            "requests.sessions.Session.request",
            side_effect=AssertionError("Unexpected outbound request"),
        ):
            response = self.client.post(
                self.endpoint, {"target": '<script>alert("x")</script>'}
            )
        self.assertContains(response, "&lt;script&gt;", status_code=400)
        self.assertNotContains(response, '<script>alert("x")</script>', status_code=400)

    def test_unresolvable_target_returns_results_instead_of_500(self):
        with patch(
            "requests.sessions.Session.request",
            side_effect=requests.ConnectionError("DNS failure"),
        ):
            response = self.client.post(self.endpoint, {"target": "test-domain.lu"})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context["cookies_result"]["status"])
        self.assertTrue(
            TestReport.objects.filter(tested_site="test-domain.lu").exists()
        )

    def test_valid_csp_and_forbidden_target_do_not_break_results(self):
        for result in (
            web_response(
                {
                    "Content-Security-Policy": "default-src 'self'; upgrade-insecure-requests;"
                }
            ),
            web_response(status=403),
            web_response({"Strict-Transport-Security": "max-age=invalid"}),
        ):
            with self.subTest(headers=dict(result.headers), status=result.status_code):
                with patch("requests.sessions.Session.request", return_value=result):
                    response = self.client.post(
                        self.endpoint, {"target": "test-domain.lu"}
                    )
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, "Overview of test-domain.lu")
