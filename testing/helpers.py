import requests
import json
from testing_platform import settings
from imap_tools import MailBox


def get_observatory_report(target):
    ################################
    # HTTP SCAN Mozilla Observatory
    ################################
    rescan = True
    if rescan is True:
        do_scan = requests.post(
            'https://http-observatory.security.mozilla.org/api/v1/analyze?host=' + target + '&rescan=true'
        ).text
    else:
        do_scan = requests.post(
            'https://http-observatory.security.mozilla.org/api/v1/analyze?host=' + target
        ).text

    json_object = json.loads(do_scan)
    headers = {}
    use = True

    if 'error' in json_object:
        if json_object['error'] == 'invalid-hostname':
            return {'error': 'You entered an invalid hostname!'}
    else:
        scan_history = json.loads(
            requests.get(
                'https://http-observatory.security.mozilla.org/api/v1/getHostHistory?host=' + target
            ).text
        )
        scan_id = json_object['scan_id']
        scan_summary = json_object

        while json_object['state'] == "PENDING" or json_object['state'] == "STARTING" or json_object[
            'state'] == "RUNNING":
            get_scan = requests.get(
                'https://http-observatory.security.mozilla.org/api/v1/analyze?host=' + target).text
            check_object = json.loads(get_scan)
            if check_object["state"] == 'FINISHED':
                use = False
                headers = {k.replace('-', '_'): v for k, v in check_object['response_headers'].items()}
                scan_id = check_object['scan_id']
                scan_summary = check_object
                break

        result_obj = json.loads(requests.get(
            'https://http-observatory.security.mozilla.org/api/v1/getScanResults?scan=' + str(scan_id)).text)

        response = {k.replace('-', '_'): v for k, v in result_obj.items()}
        if use:
            headers = {k.replace('-', '_'): v for k, v in json_object['response_headers'].items()}

        ################################
        # TLS SCAN Mozilla Observatory
        ################################
        tls_target = target.replace('www.', '')

        if rescan is True:
            do_tls_scan = json.loads(requests.post(
                'https://tls-observatory.services.mozilla.com/api/v1/scan?target=' + tls_target + '&rescan=true').text)
        else:
            do_tls_scan = json.loads(requests.post(
                'https://http-observatory.security.mozilla.org/api/v1/analyze?host=' + tls_target).text)
        tls_scan_id = do_tls_scan['scan_id']
        # TODO Finish TLS Observatory Data fetching

        return {'result': response, 'domain_name': target, 'scan_summary': scan_summary, 'headers': headers,
                'scan_history': scan_history, 'tls_results': do_tls_scan}


def dmarc_view_checker():
    # TODO this function will be used to check if the user that is asking for the report is allowed to see it.
    return None


def connect_dmarc_mail():
    # TODO change the creds with vars before commit
    mailbox = MailBox('mail.mbox.lu')
    mailbox.login('contact.testing@c3.lu', 'wkeNrqnYmmd!xkm8oJR&RRo2J9')
    return mailbox
