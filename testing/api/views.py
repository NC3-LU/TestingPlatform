from django_q import models as q_models
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.authentication import BasicAuthentication, SessionAuthentication
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from testing.models import TlsScanHistory

from .serializers import (
    AutomatedScheduledSerializer,
    AutomatedSuccessSerializer,
    TlsScanHistorySerializer,
)


#
# Model: TlsScanHistory
#
class TlsScanHistoryApiView(APIView):
    # add permission to check if user is authenticated
    authentication_classes = [SessionAuthentication, BasicAuthentication]
    permission_classes = [IsAuthenticated, IsAdminUser]

    @extend_schema(request=None, responses=TlsScanHistorySerializer)
    def get(self, request, *args, **kwargs):
        """
        List all the external tokens.
        """
        objects = TlsScanHistory.objects.all()
        serializer = TlsScanHistorySerializer(objects, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AutomatedSuccessApiView(APIView):
    # add permission to check if user is authenticated
    authentication_classes = [SessionAuthentication, BasicAuthentication]
    permission_classes = [IsAuthenticated, IsAdminUser]

    @extend_schema(request=None, responses=AutomatedSuccessSerializer)
    def get(self, request, *args, **kwargs):
        """
        List the successfull Django Q tasks.
        """
        objects = q_models.Success.objects.all()
        serializer = AutomatedSuccessSerializer(objects, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AutomatedScheduledApiView(APIView):
    # add permission to check if user is authenticated
    authentication_classes = [SessionAuthentication, BasicAuthentication]
    permission_classes = [IsAuthenticated, IsAdminUser]

    @extend_schema(request=None, responses=AutomatedScheduledSerializer)
    def get(self, request, *args, **kwargs):
        """
        List the scheduled Django Q tasks.
        """
        objects = q_models.Schedule.objects.all()
        serializer = AutomatedScheduledSerializer(objects, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
