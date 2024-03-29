from django_q import models as q_models
from rest_framework import serializers

from api import validators
from authentication.models import User
from automation.models import HttpAutomatedTest, PingAutomatedTest
from testing.models import TlsScanHistory

#
# Model: User
#


class UserInputLoginSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=200, required=True)
    password = serializers.CharField(max_length=200, required=True)

    class Meta:
        model = User
        fields = [
            "username",
            "email",
        ]


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "company_name"]


class UserInputSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=200, required=True)
    email = serializers.CharField(max_length=200, required=True)
    password = serializers.CharField(max_length=200, required=True)
    company_name = serializers.CharField(max_length=200, required=True)
    address = serializers.CharField(max_length=200, required=True)
    post_code = serializers.CharField(max_length=200, required=True)
    city = serializers.CharField(max_length=200, required=True)
    vat_number = serializers.CharField(max_length=200, required=True)

    class Meta:
        model = User
        fields = [
            "username",
            "email",
            "password",
            "company_name",
            "address",
            "post_code",
            "city",
            "vat_number",
        ]


#
# Model: AutomatedTest
#
class AutomatedTestHTTPSerializer(serializers.ModelSerializer):
    class Meta:
        model = HttpAutomatedTest
        fields = ["frequency", "time", "weekday", "monthly_test_date"]


class AutomatedTestPingSerializer(serializers.ModelSerializer):
    class Meta:
        model = PingAutomatedTest
        fields = ["frequency", "time", "weekday", "monthly_test_date"]


#
# Model: TLS Scan History
#
class TlsScanHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = TlsScanHistory
        fields = ["scan_id", "domain"]


#
# Model: AutomatedTasks
#
class AutomatedSuccessSerializer(serializers.ModelSerializer):
    class Meta:
        model = q_models.Success
        fields = ["id", "name", "func", "args", "started", "stopped", "result"]


class AutomatedScheduledSerializer(serializers.ModelSerializer):
    class Meta:
        model = q_models.Schedule
        fields = ["id", "name", "func", "schedule_type", "next_run"]


class AutomatedFailedSerializer(serializers.ModelSerializer):
    class Meta:
        model = q_models.Failure
        fields = ["id", "name", "func", "started", "stopped"]


#
# JSON serializer for system health information.
#
class HealthSerializer(serializers.Serializer):
    python_version = serializers.CharField(
        help_text="The version of Python used for the software."
    )
    database = serializers.DictField(help_text="Information about the database(s).")
    app_version = serializers.CharField(help_text="The version of the software.")
    version_url = serializers.CharField(
        help_text="The URL to the release page for the software."
    )
    email = serializers.BooleanField(
        help_text="Boolean indicating if email is correctly configured."
    )

    class Meta:
        fields = ["python_version", "database", "app_version", "version_url", "email"]


#
# InfraTesting
#
class FileSerializer(serializers.Serializer):
    file = serializers.FileField(help_text="File to check.")

    class Meta:
        fields = ["file"]

    def validate_file(self, data):
        """
        Check that the file size does not exceed the maximum allowed (as defined in settings.py).
        """
        return validators.file_size(data)


class DomainNameSerializer(serializers.Serializer):
    domain_name = serializers.CharField(
        max_length=200,
        required=True,
        help_text="Domain name.",
    )

    class Meta:
        fields = ["domain_name"]

    def validate_domain_name(self, data):
        """
        Check that data is a valid domain name.
        """
        return validators.domain_name(data)


class DomainNameAndServiceSerializer(serializers.Serializer):
    domain_name = serializers.CharField(
        max_length=200, required=True, help_text="Domain name."
    )
    service = serializers.ChoiceField(
        [("web", "Web"), ("mail", "Email")],
        required=True,
        help_text="The service to be checked.",
    )

    class Meta:
        fields = ["domain_name", "service"]

    def validate_service(self, data):
        """
        Check that data is a valid service.
        """
        return validators.service(data)

    def validate_domain_name(self, data):
        """
        Check that data is a valid domain name.
        """
        return validators.domain_name(data)
