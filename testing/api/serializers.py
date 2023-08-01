from rest_framework import serializers

from testing.models import TlsScanHistory


class TlsScanHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = TlsScanHistory
        fields = ["scan_id", "domain"]
