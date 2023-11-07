from django_q import models as q_models
from rest_framework import serializers

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
# InfraTesting
#
class FileSerializer(serializers.Serializer):
    file = serializers.FileField(help_text="File to check.")

    class Meta:
        fields = ["file"]


class IPv6Serializer(serializers.Serializer):
    ip_v6 = serializers.CharField(
        max_length=200, required=True, help_text="Domain name."
    )

    class Meta:
        fields = ["ip_v6"]


class DomainNameSerializer(serializers.Serializer):
    domain_name = serializers.CharField(
        max_length=200, required=True, help_text="Domain name."
    )

    class Meta:
        fields = ["domain_name"]


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
