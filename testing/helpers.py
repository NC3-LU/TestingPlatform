import json
import logging
import time
from io import BytesIO
from typing import Any, Dict

import checkdmarc
import pypandora
import requests

from testing.models import TlsScanHistory

logger = logging.getLogger(__name__)


def get_http_report(target, rescan):
    ################################
    # HTTP SCAN Mozilla Observatory
    ################################
    response = {}
    scan_summary = ""
    scan_history = ""

    logger.info(f"http scan: scanning {target}, with rescan set to {rescan}")

    http_url = (
        "https://http-observatory.security.mozilla.org/api/v1/analyze?host=" + target
    )
    if rescan:
        http_url += "&rescan=true"

    do_scan = requests.post(http_url).text

    json_object = json.loads(do_scan)
    headers = {}
    use = True

    if "error" in json_object:
        if json_object["error"] == "invalid-hostname":
            return {"error": "You entered an invalid hostname!"}
    else:
        scan_history = json.loads(
            requests.get(
                "https://http-observatory.security.mozilla.org/api/v1/getHostHistory?host="
                + target
            ).text
        )
        scan_id = json_object["scan_id"]
        scan_summary = json_object
        state = ""
        counter = 0

        while json_object["state"] not in ("ABORTED", "FAILED") and counter < 5:
            get_scan = requests.get(
                "https://http-observatory.security.mozilla.org/api/v1/analyze?host="
                + target
            ).text
            check_object = json.loads(get_scan)
            state = check_object.get("state", "NO_STATE")
            counter += 1
            if state == "FINISHED":
                use = False
                headers = {
                    k.replace("-", "_"): v
                    for k, v in check_object["response_headers"].items()
                }
                scan_id = check_object["scan_id"]
                scan_summary = check_object
                logger.info(f"http scan: finished scan in {counter} request(s)")
                result_obj = json.loads(
                    requests.get(
                        "https://http-observatory.security.mozilla.org/api/v1/getScanResults?scan="
                        + str(scan_id)
                    ).text
                )
                response = {k.replace("-", "_"): v for k, v in result_obj.items()}
                if use:
                    headers = {
                        k.replace("-", "_"): v
                        for k, v in json_object["response_headers"].items()
                    }
                break
            else:
                if state in (
                    "ABORTED",
                    "FAILED",
                    "PENDING",
                    "STARTING",
                    "RUNNING",
                    "NO_STATE",
                ):
                    logger.info(
                        f"http scan: got {state} after {counter} request(s) for {target}, retrying in 3s"
                    )
                    time.sleep(3)
                else:
                    logger.info(f"http scan: got unknown state {state} for {target}")
                    print(f"http scan: got unknown state {state} for {target}")

        if counter == 5 and state != "FINISHED":
            logger.warning("http scan: not finished after 5 times, skipping")

        return {
            "result": response,
            "domain_name": target,
            "scan_summary": scan_summary,
            "headers": headers,
            "scan_history": scan_history,
        }


def get_tls_report(target, rescan):
    ################################
    # TLS SCAN Mozilla Observatory
    ################################
    tls_target = target.replace("www.", "")
    tls_scan_id = ""
    url = (
        "https://tls-observatory.services.mozilla.com/api/v1/scan?target=" + tls_target
    )
    if rescan:
        url += "&rescan=true"
    try:
        do_tls_scan = json.loads(requests.post(url).text)
        tls_scan_id = do_tls_scan["scan_id"]
        TlsScanHistory.objects.update_or_create(
            domain=tls_target, defaults={"scan_id": tls_scan_id}
        )
    except ValueError:
        tls_scan_history = TlsScanHistory.objects.get(domain=tls_target)
        tls_scan_id = tls_scan_history.scan_id

    fetch_tls = json.loads(
        requests.get(
            "https://tls-observatory.services.mozilla.com/api/v1/results?id="
            + str(tls_scan_id)
        ).text
    )

    completion_perc = fetch_tls["completion_perc"]
    counter = 0
    while completion_perc != 100 and counter < 5:
        fetch_tls = json.loads(
            requests.get(
                "https://tls-observatory.services.mozilla.com/api/v1/results?id="
                + str(tls_scan_id)
            ).text
        )
        completion_perc = fetch_tls["completion_perc"]
        counter += 1
        if completion_perc == 100:
            logger.info(f"tls scan: finished scan in {counter} request(s).")
            break
        else:
            logger.info(
                f"tls scan: got {completion_perc}% done for {target} after {counter} request(s), sleeping 3s"
            )
            time.sleep(3)

    if completion_perc < 100 and counter == 5:
        logger.warning("tls scan: scan not finished after 5 tries, skipping")

    return fetch_tls


def email_check(target: str, rescan: bool) -> Dict[str, Any]:
    """Parses and validates MX, SPF, and DMARC records,
    Checks for DNSSEC deployment, Checks for STARTTLS and TLS support."""
    result = checkdmarc.check_domains([target])
    json_result = checkdmarc.results_to_json(result)
    return {
        "result": json_result,
        "domain_name": target,
    }


def file_check(file_in_memory: BytesIO, file_to_check_name: str) -> Dict[str, Any]:
    """Checks a file by submitting it to a Pandora instance."""
    pandora_root_url = "https://pandora.circl.lu/"
    pandora_cli = pypandora.PyPandora(root_url=pandora_root_url)
    analysis_result: Dict[str, Any] = {}

    # Submit the file to Pandora for analysis.
    # scan_start_time = time.time()
    result = pandora_cli.submit(file_in_memory, file_to_check_name, 50)
    if not result["success"]:
        # unsuccessfull submission of the file
        return {
            "result": analysis_result,
        }

    time.sleep(0.1)
    # Get the status of a task.
    analysis_result = pandora_cli.task_status(result["taskId"])
    time.sleep(0.1)
    loop = 0
    while loop < (50 * 10):
        analysis_result = pandora_cli.task_status(analysis_result["taskId"])
        # Handle responde from Pandora
        status = analysis_result["status"]
        if status != "WAITING":
            break
        print("Waiting...")

        # wait a little
        pass
        time.sleep(0.1)

        loop += 1
    # scan_end_time = time.time()

    analysis_result.update({"link": result["link"]})

    return {
        "result": analysis_result,
    }
