from django.contrib.auth import authenticate
from django_q import models as q_models
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.authentication import BasicAuthentication, SessionAuthentication
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import AccessToken, OutstandingToken, RefreshToken

from authentication.models import User
from automation.models import HttpAutomatedTest, PingAutomatedTest
from testing.helpers import (
    check_dkim_public_key,
    check_soa_record,
    email_check,
    file_check,
    ipv6_check,
    tls_version_check,
    web_server_check,
)
from testing.models import TlsScanHistory
from testing_platform import tools

from .serializers import (
    AutomatedFailedSerializer,
    AutomatedScheduledSerializer,
    AutomatedSuccessSerializer,
    AutomatedTestHTTPSerializer,
    AutomatedTestPingSerializer,
    DomainNameAndServiceSerializer,
    DomainNameSerializer,
    FileSerializer,
    TlsScanHistorySerializer,
    UserInputSerializer,
    UserSerializer,
)


class LoginApiView(APIView):
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        user = authenticate(username=username, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)
            response = Response(
                {"detail": "Logged in successfully."}, status=status.HTTP_200_OK
            )
            response.set_cookie(
                key="access_token",
                value=access_token,
                httponly=True,
                samesite="None",
                secure=True,  # Set to true for prod
            )

            response.set_cookie(
                key="refresh_token",
                value=refresh_token,
                httponly=True,
                samesite="None",
                secure=True,  # Set to true for prod
            )

            return response

        return Response(status=status.HTTP_401_UNAUTHORIZED)


class LogoutView(APIView):
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        # Clear the access token cookie
        response = Response()

        response.delete_cookie("access_token")
        # Clear the refresh token cookie
        refresh_token = request.COOKIES.get("refresh_token")
        response.delete_cookie("refresh_token")

        # Invalidate the refresh token on the server side
        if refresh_token:
            try:
                # Try to remove the refresh token (OutstandingToken) for the given user

                OutstandingToken.objects.filter(token=refresh_token).delete()
            except OutstandingToken.DoesNotExist as e:
                response.data = {"detail": f"Error: {str(e)}"}
                response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
                return response
                # If all operations were successfulException as e:
        response.data = {"detail": "Logged out successfully."}
        response.status_code = status.HTTP_200_OK
        return response


class CheckAuthApiView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = []

    def get(self, request):
        # Check if there's an access token in the cookies
        access_token = request.COOKIES.get("access_token")
        refresh_token = request.COOKIES.get("refresh_token")

        # If access token is present and valid
        if access_token:
            try:
                AccessToken(access_token)
                return Response({"detail": "Valid token"}, status=status.HTTP_200_OK)
            except TokenError:
                pass

        # If access token is invalid, but there's a valid refresh token
        if refresh_token:
            try:
                refresh = RefreshToken(refresh_token)
                new_access_token = str(refresh.access_token)
                # Optionally, set the new access token in the cookie
                response = Response(
                    {"detail": "Logged in. Token refreshed."}, status=status.HTTP_200_OK
                )
                response.set_cookie(
                    key="access_token", value=new_access_token, httponly=True
                )
                return response
            except TokenError:
                pass

        # If none of the above conditions are met, the user is not logged in
        return Response(
            {"detail": "You are not logged in."}, status=status.HTTP_401_UNAUTHORIZED
        )


class SystemHealthApiView(APIView):
    def get(self, request):
        """
        Returns informations concerning the health of the application.
        """
        result = tools.health()
        return Response(result)


#
# Model: User
#
class UserApiView(APIView):
    # add permission to check if user is authenticated
    authentication_classes = [
        SessionAuthentication,
        BasicAuthentication,
        JWTAuthentication,
    ]
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


class UserElementApiView(APIView):
    # add permission to check if user is authenticated
    authentication_classes = [
        SessionAuthentication,
        BasicAuthentication,
        JWTAuthentication,
    ]
    permission_classes = [IsAuthenticated, IsAdminUser]
    serializer_class = UserSerializer

    @extend_schema(request=UserInputSerializer, responses=UserSerializer)
    def put(self, request, id=None):
        """
        Update an existing user.
        """
        user = User.objects.get(id=id)
        password = request.data.get("password", None)
        if password:
            user.set_password(password)
        user.save()
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, id=None):
        """
        Delete a user.
        """
        user = User.objects.filter(id=id)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


#
# Model: AutomatedTest
#
class AutomatedTestHTTPApiView(APIView):
    # add permission to check if user is authenticated
    authentication_classes = [
        SessionAuthentication,
        BasicAuthentication,
        JWTAuthentication,
    ]
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
    authentication_classes = [
        SessionAuthentication,
        BasicAuthentication,
        JWTAuthentication,
    ]
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
    authentication_classes = [
        SessionAuthentication,
        BasicAuthentication,
        JWTAuthentication,
    ]
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
    authentication_classes = [
        SessionAuthentication,
        BasicAuthentication,
        JWTAuthentication,
    ]
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
    authentication_classes = [
        SessionAuthentication,
        BasicAuthentication,
        JWTAuthentication,
    ]
    permission_classes = [IsAuthenticated, IsAdminUser]

    @extend_schema(request=None, responses=AutomatedFailedSerializer)
    def get(self, request, *args, **kwargs):
        """
        List the failed Django Q tasks.
        """
        objects = q_models.Failure.objects.all()
        serializer = AutomatedFailedSerializer(objects, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


#
# InfraTesting
#
class InfraTestingEmailApiView(ViewSet):
    serializer_class = DomainNameSerializer

    def create(self, request, *args, **kwargs):
        """
        Parses and validates MX, SPF, and DMARC records,
        Checks for DNSSEC deployment, Checks for STARTTLS and TLS support.
        Checks for the validity of the DKIM public key.
        """
        domain_name = request.data.get("domain_name", None)
        result = email_check(domain_name)
        return Response(result, status=status.HTTP_200_OK)


class InfraTestingFileApiView(ViewSet):
    serializer_class = FileSerializer

    def create(self, request):
        """
        Submit a file to a Pandora instance.
        """
        file_uploaded = request.FILES.get("file")
        result = file_check(file_uploaded.read(), file_uploaded.name)
        return Response(result, status=status.HTTP_200_OK)


class InfraTestingIPv6ApiView(ViewSet):
    serializer_class = DomainNameSerializer

    def create(self, request, *args, **kwargs):
        """
        Triggers the IPv6 check.
        """
        domain_name = request.data.get("domain_name", None)
        result = ipv6_check(domain_name)
        return Response(result, status=status.HTTP_200_OK)


class InfraTestingSOAApiView(ViewSet):
    serializer_class = DomainNameSerializer

    def create(self, request, *args, **kwargs):
        """
        Checks the presence of a SOA record.
        """
        domain_name = request.data.get("domain_name", None)
        result = check_soa_record(domain_name)
        return Response(result, status=status.HTTP_200_OK)


class WebServerCheckApiView(ViewSet):
    serializer_class = DomainNameSerializer

    def create(self, request, *args, **kwargs):
        """
        Triggers a scan (with nmap) on a web server.
        """
        domain_name = request.data.get("domain_name", None)
        result = web_server_check(domain_name)
        return Response(result, status=status.HTTP_200_OK)


class TLSVersionCheckApiView(ViewSet):
    serializer_class = DomainNameAndServiceSerializer

    def create(self, request, *args, **kwargs):
        """
        Checks the version of TLS.
        """
        domain_name = request.data.get("domain_name", None)
        service = request.data.get("service", "web")
        result = tls_version_check(domain_name, service)
        return Response(result, status=status.HTTP_200_OK)


class DKIMPublicKeyCheckApiView(ViewSet):
    serializer_class = DomainNameSerializer

    def create(self, request, *args, **kwargs):
        """
        Triggers a scan (with nmap) on a web server.
        """
        domain_name = request.data.get("domain_name", None)
        result = check_dkim_public_key(domain_name, [])
        return Response(result, status=status.HTTP_200_OK)
