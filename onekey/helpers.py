import json
import secrets
from pathlib import Path

import jwt
import requests
from decouple import config
from django.core.files.storage import FileSystemStorage
from django.core.signing import Signer
from onekey_client import Client, FirmwareMetadata

from testing_platform import settings


def api_login():
    client = Client(api_url=settings.ONEKEY_API_URL)
    signer = Signer()
    try:
        client.login(settings.ONEKEY_API_EMAIL, settings.ONEKEY_API_PASSWORD)
        tenant = client.get_tenant("Luxembourg House of Cybersecurity")
        client.use_tenant(tenant)
    except Exception as e:
        raise e
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


def client_upload_firmware(client, firmware_analysis_request, default_product_group):
    metadata = FirmwareMetadata(
        name=firmware_analysis_request.name,
        vendor_name=firmware_analysis_request.vendor_name,
        product_name=firmware_analysis_request.product_name,
        product_group_id=default_product_group["id"],
    )
    firmware_path = Path(firmware_analysis_request.firmware_file.path)
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
        issueSeverities: [CRITICAL, HIGH, MEDIUM, INFORMATIONAL, LOW],
        complianceGuidelineIds: ["f3463279-0234-46d0-9f02-68c941b8b107"],
        analysisTechniqueDetails: true,
        includeComments: true
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
    print(res)
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
        print(res)
        report_config = next(
            cfg
            for cfg in res["allReportConfigurations"]
            if cfg["name"] == "Default Report"
        )
        return report_config


def client_generate_report(client, firmware_uuid, report_title):
    report_config = client_get_or_generate_report_config(client)
    report_config = report_config["id"]
    GENERATE_REPORT = """
    mutation M {{
      generateReport(input: {{
        reportConfigurationId: "{}",
        firmwareIds: [
          "{}"
        ],
        title: "{}",

      }}) {{
        ... on Report {{
        id,
        title,
        classification,
        generatedTime,
        downloadUrl,
        size,

       }}
       ... on MutationError {{
          count
          errors {{
            message
            code
            ... on ValidationError {{
              fieldPath
            }}
          }}
        }}
      }}
    }}
    """.format(
        report_config, firmware_uuid, report_title
    )
    res = client.query(GENERATE_REPORT)
    report = res["generateReport"]
    print(report)
    return report


def client_request_link(client, report_uuid):
    GENERATE_REPORT_LINK = """
    mutation M {{
      createReportLink (input: {{
        reportId: "{}",
        validity: 86400
      }}) {{
        ... on CreatedReportLink {{
          downloadUrl
          id
          validUntil
        }}
        ... on MutationError {{
          count
          errors {{
            message
            code
            fieldPath
          }}
        }}
      }}
    }}
    """.format(
        report_uuid
    )
    res = client.query(GENERATE_REPORT_LINK)
    return res["createReportLink"]
