from django_q import models as q_models
from rest_framework import serializers
from rest_framework.serializers import ValidationError

from authentication.models import User
from automation.models import HttpAutomatedTest, PingAutomatedTest
from testing.models import TlsScanHistory
from testing.validators import domain_name

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
# InfraTesting
#
class FileSerializer(serializers.Serializer):
    file = serializers.FileField(help_text="File to check.")

    class Meta:
        fields = ["file"]

    def validate_file(self, data):
        """
        Check that the file is not bigger than 5000000 bytes.
        """
        if data.size > 5000000:
            raise ValidationError("The file size can not be more than 5000000 bytes.")
        return data


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
        return domain_name(data)


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
        if data not in ["web", "email"]:
            raise ValidationError("Service must be 'web' or 'email'.")
        return data

    def validate_domain_name(self, data):
        """
        Check that data is a valid domain name.
        """
        return domain_name(data)
