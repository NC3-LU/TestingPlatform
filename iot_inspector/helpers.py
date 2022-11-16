from django.core.files.storage import FileSystemStorage
from django.core.signing import Signer

from testing_platform import settings

from decouple import config
from iot_inspector_client import Client, FirmwareMetadata
from pathlib import Path
import secrets
import requests
import json
import jwt


def generate_nonce():
    return secrets.token_urlsafe()


def api_login(email, password):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    payload = json.dumps(
        {
            "client_id": settings.IOT_CLIENT_ID,
            "nonce": f"{generate_nonce()}",
            "email": email,
            "password": password,
        }
    )
    endpoint = settings.IOT_API_URL + "authorize"
    id_token = requests.post(endpoint, headers=headers, data=payload).json()["id_token"]
    tenant_id = jwt.decode(
        id_token,
        options={"verify_signature": False},
        audience="NeSPys5jIT_3OKn7R_ZyBqPubkDl9amI3sGOxJLXCy4",
    )["https://www.iot-inspector.com/tenants"][0]["id"]

    payload = json.dumps(
        {
            "client_id": settings.IOT_CLIENT_ID,
            "nonce": f"{generate_nonce()}",
            "id_token": id_token,
            "tenant_id": tenant_id,
        }
    )
    endpoint = settings.IOT_API_URL + "token"
    response = requests.post(endpoint, headers=headers, data=payload).json()
    return response


def api_add_user(iotuser, token):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    endpoint = settings.IOT_API_URL + "add-user"
    signer = Signer()
    payload = json.dumps(
        {
            "email": iotuser.user.email,
            "password": signer.unsign_object(iotuser.password),
            "policy": True,
            "company_name": iotuser.user.company_name,
        }
    )
    response = requests.post(endpoint, headers=headers, data=payload)
    return response


def get_product_group_id(client):
    query = """
    query {
        allProductGroups {
            id
            name
        }
    }
    """
    res = client.query(query)
    return next(pg for pg in res["allProductGroups"] if pg["name"] == "Default")["id"]


def client_login(iot_user):
    client = Client(api_url=settings.IOT_API_URL)
    signer = Signer()
    client.login(iot_user.login, signer.unsign_object(iot_user.password))
    tenant = client.get_tenant(iot_user.user.company_name)
    client.use_tenant(tenant)
    return client


def get_default_product_group(client):
    GET_PRODUCT_GROUPS = """
    query {
      allProductGroups {
        id
        name
      }
    }
    """
    res = client.query(GET_PRODUCT_GROUPS)
    default_product_group = next(
        pg for pg in res["allProductGroups"] if pg["name"] == "Default"
    )
    return default_product_group


def client_upload_firmware(client, analysis_request, default_product_group):
    metadata = FirmwareMetadata(
        name=analysis_request.name,
        vendor_name=analysis_request.vendor_name,
        product_name=analysis_request.product_name,
        product_group_id=default_product_group["id"],
    )
    firmware_path = Path(analysis_request.file.path)
    res = client.upload_firmware(metadata, firmware_path, enable_monitoring=True)
    return res


def client_get_or_generate_report_config(client):
    GET_ALL_REPORT_CONFIGS = """
        query {
          allReportConfigurations { id, name }
        }
        """
    GENERATE_REPORT_CONFIG = """
    mutation {
      createReportConfiguration(input: {
        name: "Default Report",
        issueSeverities: [HIGH, MEDIUM, INFORMATION, LOW],
        complianceGuidelineIds: ["ed8c41a9-24fc-4f77-bb2a-7443c31cca13"],
        analysisTechniqueDetails: true
      }) {
        ... on ReportConfiguration {
          id,
        }
        ...on MutationError {
          count
          errors {
            message
            code
            ...on ValidationError {
              fieldPath
            }
          }
        }
      }
    }
    """
    res = client.query(GET_ALL_REPORT_CONFIGS)
    try:
        report_config = next(
            cfg
            for cfg in res["allReportConfigurations"]
            if cfg["name"] == "Default Report"
        )
    except StopIteration:
        report_config = None
    if report_config:
        return report_config
    else:
        client.query(GENERATE_REPORT_CONFIG)
        res = client.query(GET_ALL_REPORT_CONFIGS)
        report_config = next(
            cfg
            for cfg in res["allReportConfigurations"]
            if cfg["name"] == "Default Report"
        )
        return report_config


def client_generate_report(client, firmware_uuid):
    report_config = client_get_or_generate_report_config(client)
    report_config = report_config["id"]
    GENERATE_REPORT = """
    
    mutation M {
      generateReport(input: {
        reportConfigurationId: "%s",
        firmwareIds: [
          "%s"
        ],
        title: null,
       
      }) {
        ... on Report {
        id,
        title,
        classification,
        generatedTime,
        downloadUrl,
        size,
       
       }
       ... on MutationError {
          count
          errors {
            message
            code
            ... on ValidationError {
              fieldPath
            }
          }
        }
      }  
    }
    """ % (
        report_config,
        firmware_uuid,
    )
    res = client.query(GENERATE_REPORT)
    report = res["generateReport"]
    return report


def client_get_report_link(client, report_uuid):
    GET_ALL_REPORTS = """
    query {
      allReports { id, state, downloadUrl }
    }
    """
    res = client.query(GET_ALL_REPORTS)
    report = next(rep for rep in res["allReports"] if rep["id"] == str(report_uuid))
    return report["state"], report["downloadUrl"]


def client_get_all_reports_states(client, analysis_requests):
    GET_ALL_REPORTS = """
        query {
          allReports { id, state, downloadUrl }
        }
        """
    res = client.query(GET_ALL_REPORTS)
    states = []
    for req in analysis_requests:
        if req.report_uuid:
            state = next(
                rep for rep in res["allReports"] if rep["id"] == str(req.report_uuid)
            )["state"]
        else:
            state = "Pending"
        states.append(state.capitalize())
    return zip(analysis_requests, states)


def api_get_report(user, report_uuid):
    signer = Signer()
    iot_user = user.iotuser
    login = api_login(iot_user.user.email, signer.unsign_object(iot_user.password))
    token = login["tenant_token"]
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }

    endpoint = settings.IOT_API_URL + f"reports/{report_uuid}/pdf"
    req = requests.get(url=endpoint, headers=headers)
    return req


def get_fs_storage(user_id):
    return FileSystemStorage(location=f"{config('FILES')}/user_{user_id}/")
