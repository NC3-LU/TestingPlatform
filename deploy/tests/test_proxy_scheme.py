import unittest

import django
from django.test import RequestFactory, override_settings

from deploy import settings as deployment_settings

django.setup()


class ProxySchemeTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(
            override_settings(
                ALLOWED_HOSTS=["testing.nc3.lu"],
                SECURE_PROXY_SSL_HEADER=getattr(
                    deployment_settings, "SECURE_PROXY_SSL_HEADER", None
                ),
            )
        )

    def test_public_https_generates_https_links_through_the_internal_http_proxy(self):
        request = RequestFactory().get(
            "/login/",
            HTTP_HOST="testing.nc3.lu",
            HTTP_X_FORWARDED_PROTO="https",
        )
        self.assertTrue(request.is_secure())
        self.assertEqual(request.build_absolute_uri(), "https://testing.nc3.lu/login/")

    def test_plain_internal_http_is_not_treated_as_https(self):
        request = RequestFactory().get("/", HTTP_HOST="testing.nc3.lu")
        self.assertFalse(request.is_secure())
