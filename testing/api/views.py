from django_q import models as q_models
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.authentication import BasicAuthentication, SessionAuthentication
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from authentication.models import User
from automation.models import HttpAutomatedTest, PingAutomatedTest
from testing.models import TlsScanHistory

from .serializers import (
    AutomatedFailedSerializer,
    AutomatedScheduledSerializer,
    AutomatedSuccessSerializer,
    AutomatedTestHTTPSerializer,
    AutomatedTestPingSerializer,
    TlsScanHistorySerializer,
    UserInputSerializer,
    UserSerializer,
)


#
# Model: User
#
class UserApiView(APIView):
    # add permission to check if user is authenticated
    authentication_classes = [SessionAuthentication, BasicAuthentication]
    permission_classes = [IsAuthenticated, IsAdminUser]

    @extend_schema(request=None, responses=UserSerializer)
    def get(self, request, *args, **kwargs):
        """
        List the users.
        """
        objects = User.objects.all()
        serializer = UserSerializer(objects, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    # Create a new object
    @extend_schema(request=UserInputSerializer, responses=UserSerializer)
    def post(self, request, *args, **kwargs):
        """
        Create a new user.
        """
        password = request.data.pop("password")
        new_user = User.objects.create(**request.data)
        new_user.set_password(password)
        new_user.save()
        serializer = UserSerializer(new_user)
        return Response(serializer.data, status=status.HTTP_200_OK)


#
# Model: AutomatedTest
#
class AutomatedTestHTTPApiView(APIView):
    # add permission to check if user is authenticated
    authentication_classes = [SessionAuthentication, BasicAuthentication]
    permission_classes = [IsAuthenticated, IsAdminUser]

    @extend_schema(request=None, responses=AutomatedTestHTTPSerializer)
    def get(self, request, *args, **kwargs):
        """
        List all the external tokens.
        """
        objects = HttpAutomatedTest.objects.all()
        serializer = AutomatedTestHTTPSerializer(objects, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AutomatedTestPingApiView(APIView):
    # add permission to check if user is authenticated
    authentication_classes = [SessionAuthentication, BasicAuthentication]
    permission_classes = [IsAuthenticated, IsAdminUser]

    @extend_schema(request=None, responses=AutomatedTestPingSerializer)
    def get(self, request, *args, **kwargs):
        """
        List all the external tokens.
        """
        objects = PingAutomatedTest.objects.all()
        serializer = AutomatedTestPingSerializer(objects, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


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


#
# Model: q_models
#
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


class AutomatedFailedApiView(APIView):
    # add permission to check if user is authenticated
    authentication_classes = [SessionAuthentication, BasicAuthentication]
    permission_classes = [IsAuthenticated, IsAdminUser]

    @extend_schema(request=None, responses=AutomatedFailedSerializer)
    def get(self, request, *args, **kwargs):
        """
        List the failed Django Q tasks.
        """
        objects = q_models.Failure.objects.all()
        serializer = AutomatedFailedSerializer(objects, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
