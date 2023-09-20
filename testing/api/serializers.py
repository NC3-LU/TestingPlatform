from django_q import models as q_models
from rest_framework import serializers

from testing.models import TlsScanHistory


class TlsScanHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = TlsScanHistory
        fields = ["scan_id", "domain"]


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
