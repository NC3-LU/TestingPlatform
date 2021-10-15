import xmltodict
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from imap_tools import MailBox, AND
from subprocess import check_output
import gzip

from .helpers import get_observatory_report, connect_dmarc_mail


@login_required
def ping_test(request):
    if request.method == 'POST':
        target = request.POST['ping-target']
        """
        Returns True if host (str) responds to a ping request.
        Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.
        """
        command = ['ping', '-c', '2', target, '-q']
        # ping_result = subprocess.call(command) == 0
        ping_result = check_output(command)
        ping_result = ping_result.decode("utf-8")
        #        if ping_result == True:
        #            result = "Target successfully pinged"
        #        else:
        #            result =  "Unable to ping target"
        return render(request, 'ping_test.html', {'result': ping_result})
    else:
        return render(request, 'ping_test.html')


@login_required
def test_landing(request):
    return render(request, 'test_landing.html')


@login_required
def c3_protocols(request):
    return render(request, 'c3_protocols.html')


@login_required
def http_test(request):
    if request.method == 'POST':
        context = get_observatory_report(request.POST['target'])
        return render(request, 'check_website.html', context=context)
    else:
        return render(request, 'check_website.html')


@login_required
def spf_generator(request):
    return render(request, 'spf_generator.html')


@login_required
def dmarc_generator(request):
    return render(request, 'dmarc_generator.html')


@login_required
def dmarc_reporter(request):
    mailbox = connect_dmarc_mail()

    # TODO Add search query fetch user domains -> search for these domains in mail and display
    emails = [msg for msg in mailbox.fetch(AND(all=True))]
    mailbox.logout()

    return render(request, 'dmarc_reporter.html', {'emails': emails})


@login_required
def dmarc_shower(request, uid):
    mailbox = connect_dmarc_mail()
    email = [msg for msg in mailbox.fetch(AND(uid=uid))]
    xml_content = "None"
    record = "None"
    content_type = "None"

    for msg in email:
        for att in msg.attachments:
            content_type = att.content_type
            if "gzip" not in content_type:
                xml_content = xmltodict.parse(att.payload)
            else:
                # TODO unzip and continue
                xml_content = att.payload

    if "gzip" not in content_type:
        record = xml_content['feedback']['record']
    else:
        xml_content = gzip.decompress(xml_content)
        xml_content = xmltodict.parse(xml_content)
        record = xml_content['feedback']['record']

    if not isinstance(record, list):
        record = [record]

    return render(request, 'dmarc_shower.html',
                  {'content': email, 'report': xml_content, 'record': record})
