import datetime
import ipaddress
import re
import socket
import time
import io

import jinja2
import xmltodict

from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

import zapv2
from ipwhois import IPDefinedError, IPWhois
from zapv2 import ZAPv2
from reportlab.pdfgen import canvas

from django.http import FileResponse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.files.base import ContentFile
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from testing_platform import settings

from .forms import DMARCRecordForm, SPFRecordForm
from .helpers import (
    check_dkim_public_key,
    check_soa_record,
    email_check,
    file_check,
    get_http_report,
    ipv6_check,
    tls_version_check,
    web_server_check,
    check_dnssec,
    check_mx,
    check_spf,
    check_dmarc,
    check_tls,
    check_dkim
)

from .zap import zap_scan

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
        # if "rescan" in request.POST:
        #  context["rescan"] = True

        context.update(get_http_report(request.POST["target"], False))
        # context.update(ipv6_check(request.POST["target"], None))

        try:
            tls_results = tls_version_check(request.POST["target"], "web")
            context["tls_results"] = tls_results["result"]
            context["tls_lowest_sec_level"] = tls_results["lowest_sec_level"]
        except Exception:
            pass

        nb_tests += 1
        response = render(request, "check_website.html", context)
        response.set_cookie("nb_tests", nb_tests)
        return response
    else:
        return render(request, "check_website.html")


def zap_test(request):
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
        api_key = settings.ZAP_API_KEY
        json_report, html_report = zap_scan(target, api_key)
        nb_tests += 1
        context = json_report['site'][0]
        response = render(request, "check_zap.html", context)
        response.set_cookie("nb_tests", nb_tests)
        print("wat")
        return response
        # return HttpResponse(html_report)
    else:
        return render(request, "check_zap.html")


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
            nb_tests = int(request.COOKIES.get("nb_tests", 0))
        except ValueError:
            nb_tests = 0
        if nb_tests >= 3 and not request.user.is_authenticated:
            messages.error(
                request,
                "You reached the maximum number of tests. Please create an account.",
            )
            return redirect("signup")
        target = request.POST["target"]
        if not check_soa_record(target):
            context = {"status": False, "statusmessage": "The given domain is invalid!"}
        else:
            dkim_selector = "default"  # You may want to allow user input for this

            context['domain'] = target
            context['dnssec'] = check_dnssec(target)
            mx_servers = check_mx(target)
            context['mx'] = {'servers': mx_servers, 'tls': check_tls(mx_servers)}
            context['spf'], context['spf_valid'] = check_spf(target)
            context['dmarc'], context['dmarc_valid'] = check_dmarc(target)
            context['dkim'], context['dkim_valid'] = check_dkim(target, dkim_selector)

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
        response = render(request, "check_infra.html", context)
        response.set_cookie("nb_tests", nb_tests)
        return response
    else:
        return render(request, "check_infra.html")


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
                mailto=data["mailto"],
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
def record_generator(request):
    spf_form = SPFRecordForm()
    dmarc_form = DMARCRecordForm(user=request.user)
    context = {}

    if request.method == "POST":
        if 'spf' in request.POST:
            spf_form = SPFRecordForm(request.POST)
            if spf_form.is_valid():
                data = spf_form.cleaned_data
                record = "v=spf1 mx "
                hosts = data["hosts"].split(",")
                for host in hosts:
                    host = host.strip()
                    if host:
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
                                "One of the specified hosts/IP addresses does not match the expected format. Please correct your entered data."
                            )
                            context = {"spf_form": spf_form, "dmarc_form": dmarc_form}
                            return render(request, "email_policy_generator.html", context)
                record += data["policy"]
                context["spf_record"] = record

        elif 'dmarc' in request.POST:
            dmarc_form = DMARCRecordForm(user=request.user, data=request.POST)
            if dmarc_form.is_valid():
                data = dmarc_form.cleaned_data
                report = DMARCRecord(
                    user=request.user,
                    domain=data["domain"],
                    policy=data["policy"],
                    spf_policy=data["spf_policy"],
                    dkim_policy=data["dkim_policy"],
                    mailto=data["mailto"],
                )
                report.save()
                context = {
                    "dmarc_form": dmarc_form,
                    "txt_record": report.txt_record,
                    "dmarc_record": report.dmarc_record,
                }

    context["spf_form"] = spf_form
    context["dmarc_form"] = dmarc_form
    return render(request, "email_policy_generator.html", context)


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


def export_pdf(request, test):
    # Create a file-like buffer to receive PDF data.
    buffer = io.BytesIO()

    # Create the PDF object, using the buffer as its "file."
    p = canvas.Canvas(buffer)

    # Draw things on the PDF. Here's where the PDF generation happens.
    # See the ReportLab documentation for the full list of functionality.

    # Close the PDF object cleanly, and we're done.
    p.showPage()
    p.save()

    # FileResponse sets the Content-Disposition header so that browsers
    # present the option to save the file.
    buffer.seek(0)
    return FileResponse(buffer, as_attachment=True, filename="hello.pdf")


def pdf_from_template(request, test):
    return HttpResponse(request)
