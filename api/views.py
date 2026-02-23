from django.contrib.auth import authenticate
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.authentication import BasicAuthentication, SessionAuthentication
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import AccessToken, OutstandingToken, RefreshToken

from authentication.models import User
from testing.helpers import (
    check_dkim,
    check_soa_record,
    email_check,
    file_check,
    ipv6_check,
    tls_version_check,
    web_server_check,
)
from testing.models import TlsScanHistory
from testing_platform import tools

import logging

from .serializers import (
    DomainNameAndServiceSerializer,
    DomainNameSerializer,
    FileSerializer,
    HealthSerializer,
    TlsScanHistorySerializer,
    UserInputSerializer,
    UserSerializer,
)

logger = logging.getLogger(__name__)


class LoginApiView(APIView):
    authentication_classes = [JWTAuthentication]
    throttle_scope = "auth"

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        user = authenticate(username=username, password=password)

        if user is not None:
            logger.info("API login successful for user '%s'", username)
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
                samesite="Lax",
                secure=True,
            )

            response.set_cookie(
                key="refresh_token",
                value=refresh_token,
                httponly=True,
                samesite="Lax",
                secure=True,
            )

            return response

        logger.warning("API login failed for user '%s'", username)
        return Response(status=status.HTTP_401_UNAUTHORIZED)


class LogoutView(APIView):
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        response = Response()
        response.delete_cookie("access_token")

        refresh_token = request.COOKIES.get("refresh_token")
        response.delete_cookie("refresh_token")

        # Invalidate the refresh token on the server side
        if refresh_token:
            OutstandingToken.objects.filter(token=refresh_token).delete()

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
    @extend_schema(request=None, responses=HealthSerializer)
    def get(self, request, *args, **kwargs):
        """
        Returns informations concerning the health of the application.
        """
        result = tools.health()
        serializer = HealthSerializer(result)
        return Response(serializer.data, status=status.HTTP_200_OK)


class SystemUpdateApiView(APIView):
    authentication_classes = [
        SessionAuthentication,
        BasicAuthentication,
        JWTAuthentication,
    ]
    permission_classes = [IsAuthenticated, IsAdminUser]

    @extend_schema(request=None, responses=None)
    def get(self, request, *args, **kwargs):
        """
        Triggers the update of the software.
        """
        cmd = ["./contrib/update.sh"]
        tools.exec_cmd_no_wait(cmd)
        return Response({"message": "Update triggered."}, status=status.HTTP_200_OK)


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
        serializer = UserInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data
        password = validated.pop("password")
        new_user = User.objects.create(
            username=validated.get("username"),
            email=validated.get("email", ""),
            company_name=validated.get("company_name", ""),
            address=validated.get("address", ""),
            post_code=validated.get("post_code", ""),
            city=validated.get("city", ""),
            vat_number=validated.get("vat_number", ""),
        )
        new_user.set_password(password)
        new_user.save()
        logger.info("API user created: '%s'", new_user.username)
        return Response(UserSerializer(new_user).data, status=status.HTTP_201_CREATED)


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
        logger.info("API user deleted: id=%s", id)
        return Response(status=status.HTTP_204_NO_CONTENT)


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
# InfraTesting
#
class InfraTestingEmailApiView(APIView):
    authentication_classes = [
        SessionAuthentication,
        BasicAuthentication,
        JWTAuthentication,
    ]
    permission_classes = [IsAuthenticated]
    throttle_scope = "infra_testing"
    serializer_class = DomainNameSerializer
    serializer = DomainNameSerializer

    def post(self, request):
        """
        Parses and validates MX, SPF, and DMARC records,
        Checks for DNSSEC deployment, Checks for STARTTLS and TLS support.
        Checks for the validity of the DKIM public key.
        """
        serializer = self.serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        domain_name = serializer.validated_data["domain_name"]
        result = email_check(domain_name)
        return Response(result, status=status.HTTP_200_OK)


class InfraTestingFileApiView(APIView):
    authentication_classes = [
        SessionAuthentication,
        BasicAuthentication,
        JWTAuthentication,
    ]
    permission_classes = [IsAuthenticated]
    throttle_scope = "infra_testing_expensive"
    serializer_class = FileSerializer
    serializer = FileSerializer

    def post(self, request):
        """
        Submit a file to a Pandora instance.
        """
        serializer = self.serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        file_uploaded = serializer.validated_data["file"]
        result = file_check(file_uploaded.read(), file_uploaded.name)
        return Response(result, status=status.HTTP_200_OK)


class InfraTestingIPv6ApiView(APIView):
    authentication_classes = [
        SessionAuthentication,
        BasicAuthentication,
        JWTAuthentication,
    ]
    permission_classes = [IsAuthenticated]
    throttle_scope = "infra_testing"
    serializer_class = DomainNameSerializer
    serializer = DomainNameSerializer

    def post(self, request):
        """
        Triggers the IPv6 check.
        """
        serializer = self.serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        domain_name = serializer.validated_data["domain_name"]
        result = ipv6_check(domain_name)
        return Response(result, status=status.HTTP_200_OK)


class InfraTestingSOAApiView(APIView):
    authentication_classes = [
        SessionAuthentication,
        BasicAuthentication,
        JWTAuthentication,
    ]
    permission_classes = [IsAuthenticated]
    throttle_scope = "infra_testing"
    serializer_class = DomainNameSerializer
    serializer = DomainNameSerializer

    def post(self, request):
        """
        Checks the presence of a SOA record.
        """
        serializer = self.serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        domain_name = serializer.validated_data["domain_name"]
        result = check_soa_record(domain_name)
        return Response(result, status=status.HTTP_200_OK)


class WebServerCheckApiView(APIView):
    authentication_classes = [
        SessionAuthentication,
        BasicAuthentication,
        JWTAuthentication,
    ]
    permission_classes = [IsAuthenticated]
    throttle_scope = "infra_testing_expensive"
    serializer_class = DomainNameSerializer
    serializer = DomainNameSerializer

    def post(self, request):
        """
        Triggers a scan (with nmap) on a web server.
        """
        serializer = self.serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        domain_name = serializer.validated_data["domain_name"]
        result = web_server_check(domain_name)
        return Response(result, status=status.HTTP_200_OK)


class TLSVersionCheckApiView(APIView):
    authentication_classes = [
        SessionAuthentication,
        BasicAuthentication,
        JWTAuthentication,
    ]
    permission_classes = [IsAuthenticated]
    throttle_scope = "infra_testing"
    serializer_class = DomainNameAndServiceSerializer
    serializer = DomainNameAndServiceSerializer

    def post(self, request):
        """
        Checks the version of TLS.
        """
        serializer = self.serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        domain_name = serializer.validated_data["domain_name"]
        service = serializer.validated_data["service"]
        result = tls_version_check(domain_name, service)
        return Response(result, status=status.HTTP_200_OK)


class DKIMPublicKeyCheckApiView(APIView):
    authentication_classes = [
        SessionAuthentication,
        BasicAuthentication,
        JWTAuthentication,
    ]
    permission_classes = [IsAuthenticated]
    throttle_scope = "infra_testing"
    serializer_class = DomainNameSerializer
    serializer = DomainNameSerializer

    def post(self, request):
        """
        Checks the DKIM configuration for a domain.
        """
        serializer = self.serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        domain_name = serializer.validated_data["domain_name"]
        result = check_dkim(domain_name, selectors=[])
        return Response(result, status=status.HTTP_200_OK)
