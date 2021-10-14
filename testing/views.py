import xmltodict
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from imap_tools import MailBox, AND

from subprocess import check_output

from .helpers import get_observatory_report, connect_dmarc_mail


# Create your views here.


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
def check_website(request):
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


def dmarc_shower(request, uid):
    mailbox = connect_dmarc_mail()
    email = [msg for msg in mailbox.fetch(AND(uid=uid))]
    xml_content = "None"
    type = "None"
    record = "None"

    for msg in email:
        for att in msg.attachments:
            if att.content_type.find('gzip') != -1:
                xml_content = None

            else:
                xml_content = xmltodict.parse(att.payload)

    # record = xml_content['feedback']['record']

    # if not isinstance(record, list):
    # record = [record]

    return render(request, 'dmarc_shower.html',
                  {'content': email, 'report': xml_content, 'record': record})
