import datetime
import ipaddress
import re
import socket
import time
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

import xmltodict
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.files.base import ContentFile
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from ipwhois import IPDefinedError, IPWhois
from zapv2 import ZAPv2

from testing_platform import settings

from .forms import DMARCRecordForm, SPFRecordForm
from .helpers import (
    check_dkim_public_key,
    check_soa_record,
    email_check,
    file_check,
    get_http_report,
    get_tls_report,
    ipv6_check,
    web_server_check,
    tls_version_check,
)
from .models import DMARCRecord, DMARCReport, MailDomain


@login_required
def ping_test(request):
    if request.method == "POST":
        target = request.POST["ping-target"].strip()
        try:
            target = socket.gethostbyname(target)
        except socket.gaierror:
            messages.error(request, "Could not resolve hostname.")
            return redirect("ping_test")
        try:
            obj = IPWhois(target)
        except IPDefinedError:
            messages.error(
                request, "You are not authorized to test this host / ip address."
            )
            return redirect("ping_test")
        except ValueError:
            messages.error(request, "The hostname could not be resolved")
            return redirect("ping_test")
        ping_result = obj.lookup_rdap(depth=1)
        # command = ['ping', '-c', '2', target, '-q']
        # ping_result = subprocess.call(command) == 0
        # ping_result = check_output(command)
        # ping_result = ping_result.decode("utf-8")
        #        if ping_result == True:
        #            result = "Target successfully pinged"
        #        else:
        #            result =  "Unable to ping target"
        return render(request, "whois_lookup.html", {"result": ping_result})
    else:
        return render(request, "whois_lookup.html")


@login_required
def test_landing(request):
    return render(request, "test_landing.html")


def http_test(request):
    if request.method == "POST":
        try:
            nb_tests = int(request.COOKIES["nb_tests"])
        except KeyError:
            nb_tests = 0
        if nb_tests == 3 and not request.user.is_authenticated:
            messages.error(
                request,
                "You reached the maximum number of tests. Please create an account.",
            )
            return redirect("signup")
        context = {"rescan": False}
        if "rescan" in request.POST:
            context["rescan"] = True
        context.update(get_http_report(request.POST["target"], context["rescan"]))
        context.update(ipv6_check(request.POST["target"], None))

       # context["tls_results"] = tls_version_check(
       #     request.POST["target"]
       # )

        # context.update(ipv6_check("nc3.lu", None))
        nb_tests += 1
        response = render(request, "check_website.html", context)
        response.set_cookie("nb_tests", nb_tests)
        return response
    else:
        return render(request, "check_website.html")


def web_test(request):
    # TODO check that for a new scan a new session is created an after
    #  getting the result it shall be closed
    if request.method == "POST":
        ipv6 = ipv6_check(request.POST["target"], None)
        # Command used to start zap locally (ubuntu)
        # zap.sh -daemon -config api.key=12345 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
        # The URL of the application to be tested
        target = request.POST["target"]
        # Change to match the API key set in ZAP, or use None if the API key is disabled
        apikey = "12345"

        # By default ZAP API client will connect to port 8080
        zap = ZAPv2(
            apikey=apikey,
            proxies={"http": "http://127.0.0.1:8081", "https": "http://127.0.0.1:8081"},
        )

        scanid = zap.spider.scan("http://" + target)
        while int(zap.spider.status(scanid)) < 100:
            time.sleep(1)

        results_url = zap.spider.results(scanid)
        while int(zap.pscan.records_to_scan) > 0:
            # Loop until the passive scan has finished
            print("Records to passive scan : " + zap.pscan.records_to_scan)
            time.sleep(2)
        alerts = zap.core.alerts()

        # Create an empty list to hold the matching alerts
        matching_alerts = []

        # Loop through the alerts
        for alert in alerts:
            # Check if the alert's URL is in the list
            if alert["url"] in results_url:
                if alert["confidence"] == "High":
                    # If it is, append the alert to the matching_alerts list
                    matching_alerts.append(alert)

        return render(
            request,
            "check_webapp.html",
            {
                "results_url": results_url,
                "alerts": matching_alerts,
                "target": target,
                "ipv6": ipv6,
            },
        )

    else:
        return render(request, "check_webapp.html")


def email_test(request):
    context = {}
    if request.method == "POST":
        try:
            nb_tests = int(request.COOKIES["nb_tests"])
        except KeyError:
            nb_tests = 0
        if nb_tests == 3 and not request.user.is_authenticated:
            messages.error(
                request,
                "You reached the maximum number of tests. Please create an account.",
            )
            return redirect("signup")
        target = request.POST["target"]
        if not check_soa_record(target):
            context = {"status": False, "statusmessage": "The given domain is invalid!"}
        else:
            context.update(email_check(target))
            context.update(check_dkim_public_key(target, []))
            context.update(ipv6_check(target, None))
            context.update({"status": True})
            # for host in email_results['result']['mx']['hosts']:
            # context["ipv6_mx"] = ipv6_check(
            #        host["hostname"], None
            #    )
            #    context["tls_mx"] = tls_version_check(
            #        host["hostname"]
            #    )
        nb_tests += 1
        response = render(request, "check_email.html", {"result": context})
        response.set_cookie("nb_tests", nb_tests)
        return response
    else:
        return render(request, "check_email.html")


def file_test(request):
    if request.method == "POST" and request.FILES["target"]:
        context: Dict[str, Any] = {}
        file_to_check = request.FILES["target"].read()
        file_to_check_name = request.FILES["target"].name
        context.update(file_check(file_to_check, file_to_check_name))
        return render(request, "check_file.html", context)
    else:
        return render(request, "check_file.html")


def ipv6_test(request):
    if request.method == "POST":
        try:
            nb_tests = int(request.COOKIES["nb_tests"])
        except KeyError:
            nb_tests = 0
        if nb_tests == 3 and not request.user.is_authenticated:
            messages.error(
                request,
                "You reached the maximum number of tests. Please create an account.",
            )
            return redirect("signup")
        context = {}
        context.update(ipv6_check(request.POST["target"], None))
        nb_tests += 1
        response = render(request, "check_ipv6.html", context)
        response.set_cookie("nb_tests", nb_tests)
        return response
    else:
        return render(request, "check_ipv6.html")


def web_server_test(request):
    if request.method == "POST":
        try:
            nb_tests = int(request.COOKIES["nb_tests"])
        except KeyError:
            nb_tests = 0
        if nb_tests == 3 and not request.user.is_authenticated:
            messages.error(
                request,
                "You reached the maximum number of tests. Please create an account.",
            )
            return redirect("signup")
        context = {}
        context.update(web_server_check(request.POST["target"]))
        nb_tests += 1
        response = render(request, "check_web_server.html", context)
        response.set_cookie("nb_tests", nb_tests)
        return response
    else:
        return render(request, "check_web_server.html")


@login_required
def spf_generator(request):
    if request.method == "POST":
        form = SPFRecordForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            record = "v=spf1 mx "
            hosts = data["hosts"].split(",")
            for host in hosts:
                if host:
                    if " " in host:
                        host = host.replace(" ", "")
                    try:
                        match_ip = ipaddress.ip_address(host)
                    except ValueError:
                        match_ip = None
                    match_hostname = re.fullmatch(
                        r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$", host
                    )
                    if match_ip:
                        record += f"ip{match_ip.version}:{host} "
                    elif match_hostname:
                        record += f"a:{host} "
                    else:
                        messages.error(
                            request,
                            "One of the specified host / ip address does not match "
                            "expected format."
                            " Please correct your entered data.",
                        )
                        return render(request, "spf_generator.html", {"form": form})
            record += data["policy"]
            return render(
                request, "spf_generator.html", {"form": form, "record": record}
            )
    else:
        form = SPFRecordForm()
        return render(request, "spf_generator.html", {"form": form})


@login_required
def dmarc_generator(request):
    if not request.user.maildomain_set.filter(user=request.user).last():
        messages.error(request, "Please add a mail domain in your profile first.")
        return redirect("test_index")
    if request.method == "POST":
        form = DMARCRecordForm(request.user, request.POST)
        if form.is_valid():
            data = form.cleaned_data
            try:
                domain = MailDomain.objects.filter(user=request.user).get(
                    domain=data["domain"]
                )
            except MailDomain.DoesNotExist:
                messages.error(
                    request, "This domain is not in your managed mail domains"
                )
                return render(request, "dmarc_generator.html", {"form": form})
            report = DMARCRecord(
                user=request.user,
                domain=domain,
                policy=data["policy"],
                spf_policy=data["spf_policy"],
                dkim_policy=data["dkim_policy"],
            )
            report.save()
            context = {
                "form": form,
                "txt": report.txt_record,
                "record": report.dmarc_record,
            }
            return render(request, "dmarc_generator.html", context=context)
    else:
        uri = request.build_absolute_uri()
        if urlparse(uri).query:
            domain = MailDomain.objects.get(domain=urlparse(uri).query)
            try:
                record = DMARCRecord.objects.get(user=request.user, domain=domain.id)
                context = {
                    "form": DMARCRecordForm(instance=record, user=request.user),
                    "txt": record.txt_record,
                    "record": record.dmarc_record,
                }
                return render(request, "dmarc_generator.html", context=context)
            except DMARCRecord.DoesNotExist:
                record = None
                form = DMARCRecordForm(initial={"domain": domain}, user=request.user)
        else:
            form = DMARCRecordForm(user=request.user)
    return render(request, "dmarc_generator.html", {"form": form})


@login_required
def dmarc_reporter(request):
    domains = MailDomain.objects.filter(user=request.user)
    records = DMARCRecord.objects.filter(user=request.user)
    domain_reports = {}
    if domains:
        for domain in domains:
            try:
                record = records.get(domain=domain)
            except DMARCRecord.DoesNotExist:
                record = None
            if record:
                try:
                    reports = DMARCReport.objects.filter(dmarc_record=record)
                    domain_reports[domain] = list(reports)
                except DMARCReport.DoesNotExist:
                    domain_reports[domain] = []
    return render(request, "dmarc_reporter.html", {"domain_reports": domain_reports})


@login_required
def dmarc_shower(request, domain, mailfrom, timestamp):
    dmarc_report = DMARCReport.objects.get(
        mail_from=mailfrom, timestamp=timestamp, dmarc_record__domain__domain=domain
    )
    if (
        dmarc_report.dmarc_record.user == request.user
        and request.user.maildomain_set.filter(domain=domain)
    ):
        report = xmltodict.parse(dmarc_report.report)
        record = report["feedback"]["record"]
        if not isinstance(record, list):
            record = [record]
        return render(
            request,
            "dmarc_shower.html",
            {
                "report": report,
                "records": record,
                "domain": domain,
                "timestamp": timestamp,
                "mailfrom": mailfrom,
            },
        )
    else:
        messages.error(request, "Unauthorized")
        return redirect("index")


@login_required
def dmarc_dl(request, domain, mailfrom, timestamp):
    dmarc_report = DMARCReport.objects.get(
        mail_from=mailfrom, timestamp=timestamp, dmarc_record__domain__domain=domain
    )
    if (
        dmarc_report.dmarc_record.user == request.user
        and request.user.maildomain_set.filter(domain=domain)
    ):
        report = dmarc_report.report
        file = ContentFile(content=report)
        response = HttpResponse(
            file,
            headers={
                "Content-Type": "application/xml",
                "Content-Disposition": f"attachment; "
                                       f'filename="dmarc_{domain}_{mailfrom}_{timestamp}.xml"',
            },
        )
        return response
    else:
        messages.error(request, "Unauthorized")
        return redirect("index")


@csrf_exempt
@require_http_methods("POST")
def dmarc_upload(request):
    uri = request.build_absolute_uri()
    params = parse_qs(urlparse(uri).query)
    if params["api-key"][0] == settings.DMARC_API_KEY:
        record = DMARCRecord.objects.get(mailto__iexact=params["to"][0])
        report = request.POST["report"]
        dmarc_report = DMARCReport(
            dmarc_record=record,
            timestamp=int(datetime.datetime.now().timestamp()),
            mail_from=params["from"][0],
            report=report,
        )
        dmarc_report.save()
        return HttpResponse(status=200)
    else:
        return HttpResponse(status=401)
