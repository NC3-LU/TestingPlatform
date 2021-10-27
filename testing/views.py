import datetime

import xmltodict
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib import messages
from imap_tools import MailBox, AND
from subprocess import check_output
import gzip
from urllib.parse import urlparse, parse_qs

from .helpers import get_observatory_report
from django.views.decorators.http import require_http_methods

from authentication.models import User
from .models import DMARCRecord, DMARCReport, MailDomain
from .forms import DMARCRecordForm

from testing_platform import settings


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
    if not request.user.maildomain_set.filter(user=request.user).last():
        print(request.user.maildomain_set.filter(user=request.user).last())
        messages.error(request, 'Please add a mail domain in your profile first.')
        return redirect('test_index')
    else:
        domains = MailDomain.objects.filter(user=request.user)
        return render(request, 'spf_generator.html', {'domains': domains})


@login_required
def dmarc_generator(request):
    if not request.user.maildomain_set.filter(user=request.user).last():
        print(request.user.maildomain_set.filter(user=request.user).last())
        messages.error(request, 'Please add a mail domain in your profile first.')
        return redirect('test_index')
    if request.method == 'POST':
        form = DMARCRecordForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            report = DMARCRecord(
                user=request.user,
                domain=data['domain'],
                policy=data['policy'],
                spf_policy=data['spf_policy'],
                dkim_policy=data['dkim_policy']
            )
            report.save()
            context = {'form': form, 'txt': report.txt_record, 'record': report.dmarc_record}
            return render(request, 'dmarc_generator.html', context=context)
    else:
        uri = request.get_raw_uri()
        if urlparse(uri).query:
            domain = MailDomain.objects.get(domain=urlparse(uri).query)
            form = DMARCRecordForm(initial={'domain': domain})
        else:
            form = DMARCRecordForm()
    return render(request, 'dmarc_generator.html', {'form': form})


@login_required
def dmarc_reporter(request):
    domains = MailDomain.objects.filter(user=request.user)
    reports = DMARCRecord.objects.filter(user=request.user)
    domain_reports = []
    if domains:
        for domain in domains:
            try:
                report = DMARCRecord.objects.filter(user=request.user).get(domain=domain)
            except DMARCRecord.DoesNotExist:
                report = None
            domain_reports.append((domain, report))
    return render(request, 'dmarc_reporter.html', {'domain_reports': domain_reports})


@login_required
def dmarc_shower(request, domain, mailfrom, timestamp):
    dmarc_report = DMARCReport.objects.get(mail_from=mailfrom, timestamp=timestamp)
    report = xmltodict.parse(dmarc_report.report)
    record = report['feedback']['record']
    if not isinstance(record, list):
        record = [record]
    return render(request, 'dmarc_shower.html', {'report': report, 'records': record, 'domain': domain,
                                                 'timestamp': timestamp, 'mailfrom': mailfrom})


@csrf_exempt
@require_http_methods("POST")
def dmarc_upload(request):
    uri = request.get_raw_uri()
    params = parse_qs(urlparse(uri).query)
    if params['api-key'][0] == settings.DMARC_API_KEY:
        record = DMARCRecord.objects.get(mailto=params['to'][0])
        report = request.POST['report']
        dmarc_report = DMARCReport(
            dmarc_record=record,
            timestamp=int(datetime.datetime.now().timestamp()),
            mail_from=params['from'][0],
            report=report
        )
        dmarc_report.save()
        return HttpResponse(status=200)
    else:
        return HttpResponse(status=401)
