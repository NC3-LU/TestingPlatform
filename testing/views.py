import datetime
import ipaddress
import os
import re
import socket
from time import sleep

import xmltodict
import weasyprint
import matplotlib.pyplot as plt
import base64
from pylookyloo import Lookyloo

from io import BytesIO
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse
from PIL import Image

from ipwhois import IPDefinedError, IPWhois

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.files.base import ContentFile
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.template.loader import get_template

from testing_platform import settings

from .forms import DMARCRecordForm, SPFRecordForm
from .helpers import (
    check_soa_record,
    file_check,
    ipv6_check,
    web_server_check,
    check_dnssec,
    check_spf,
    check_dmarc,
    check_hsts,
    check_csp,
    check_cookies,
    check_cors,
    check_https_redirect,
    check_referrer_policy,
    check_sri,
    check_x_content_type_options,
    check_security_txt,
    get_capture_result,
    get_recent_captures
)
from .models import DMARCRecord, DMARCReport, MailDomain, TestReport


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

# def zap_test(request):
#     if request.method == "POST":
#         try:
#             nb_tests = int(request.COOKIES["nb_tests"])
#         except KeyError:
#             nb_tests = 0
#         if nb_tests == 3 and not request.user.is_authenticated:
#             messages.error(
#                 request,
#                 "You reached the maximum number of tests. Please create an account.",
#             )
#             return redirect("signup")
#         target = request.POST["target"]
#         api_key = settings.ZAP_API_KEY
#         # json_report, html_report = zap_scan(target, api_key)
#         # context = json_report['site'][0]
#         alerts = zap_scan(target, api_key)
#         context = {'alerts': alerts, 'target': target}
#         nb_tests += 1
#         response = render(request, "check_zap.html", context)
#
#         try:
#             test_report = TestReport.objects.get(tested_site=target, test_ran="zap")
#             test_report.report = context
#             test_report.save()
#         except TestReport.DoesNotExist:
#             test_report = TestReport.objects.get_or_create(
#                 tested_site=target,
#                 test_ran="zap",
#                 report=context
#             )
#         response.set_cookie("nb_tests", nb_tests)
#         return response
#         # return HttpResponse(html_report)
#     else:
#         return render(request, "check_zap.html")


@csrf_exempt
def check_website_security(request):
    if request.method == 'POST':
        domain = request.POST.get('target')

        csp_result = check_csp(domain)
        cookies_result = check_cookies(domain)
        cors_result = check_cors(domain)
        https_redirect_result = check_https_redirect(domain)
        referrer_policy_result = check_referrer_policy(domain)
        sri_result = check_sri(domain)
        x_content_type_options_result = check_x_content_type_options(domain)
        hsts_result = check_hsts(domain)
        security_txt_result = check_security_txt(domain)

        context = {
            'domain': domain,
            'csp_result': csp_result,
            'cookies_result': cookies_result,
            'cors_result': cors_result,
            'https_redirect_result': https_redirect_result,
            'referrer_policy_result': referrer_policy_result,
            'sri_result': sri_result,
            'x_content_type_options_result': x_content_type_options_result,
            'hsts_result': hsts_result,
            'security_txt_result': security_txt_result
        }

        try:
            test_report = TestReport.objects.get(tested_site=domain, test_ran="web-test")
            test_report.report = context
            test_report.save()
        except TestReport.DoesNotExist:
            test_report = TestReport.objects.get_or_create(
                tested_site=domain,
                test_ran="web-test",
                report=context
            )
        return render(request, 'check_webapp.html', context)

    return render(request, 'check_webapp.html')


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
            #mx_servers = check_mx(target)
            #context['mx'] = {'servers': mx_servers, 'tls': check_tls(mx_servers)}

            context['spf'] = check_spf(target)


            context['dmarc'] = check_dmarc(target)
            #context['dkim'], context['dkim_valid'] = check_dkim(target, dkim_selector)

        try:
            test_report = TestReport.objects.get(tested_site=target, test_ran="email-test")
            test_report.report = context
            test_report.save()
        except TestReport.DoesNotExist:
            test_report = TestReport.objects.get_or_create(
                tested_site=target,
                test_ran="email-test",
                report=context
            )

        nb_tests += 1
        response = render(request, "check_email.html", context)
        response.set_cookie("nb_tests", nb_tests)
        return response
    else:
        return render(request, "check_email.html")


def file_test(request):
    if request.method == "POST":
        if "target" in request.FILES:
            context: Dict[str, Any] = {}
            file_to_check = request.FILES["target"].read()
            file_to_check_name = request.FILES["target"].name
            context.update(file_check(file_to_check, file_to_check_name))
            return render(request, "check_file.html", context)
        else:
            return render(request, "check_file.html", {"error": "There was an error with the provided file. Please try again later."})
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
        domain = request.POST["target"]
        context = {'domain': domain}
        context.update(web_server_check(domain))

        try:
            test_report = TestReport.objects.get(tested_site=domain, test_ran="infra-test")
            test_report.report = context
            test_report.save()
        except TestReport.DoesNotExist:
            test_report = TestReport.objects.get_or_create(
                tested_site=domain,
                test_ran="infra-test",
                report=context
            )

        nb_tests += 1
        response = render(request, "check_services.html", context)
        response.set_cookie("nb_tests", nb_tests)
        return response
    else:
        return render(request, "check_services.html")


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
                            return render(request, "email_policy_generator.html",
                                          context)
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


@login_required
def pdf_from_template(request, test, site):
    report = TestReport.objects.get(tested_site=site, test_ran=test).report

    css_path = os.path.join(settings.STATIC_DIR, 'css/style.css')
    bootstrap_path = os.path.join(settings.STATIC_DIR, 'npm_components/bootstrap/dist/css/bootstrap.css')

    with open(css_path, 'r') as f:
        css = f.read()

    with open(bootstrap_path, 'r') as f:
        bootstrap = f.read()

    css_content = bootstrap + '\n' + css

    # Calculate stats
    count_good = 0
    count_vulnerable = 0
    if test == "web-test":
        for key, value in report.items():
            if isinstance(value, dict) and 'status' in value:
                if value['status'] is False:
                    count_vulnerable += 1
                else:
                    count_good += 1

    elif test == "email-test":
        if report['spf']['valid'] is True:
            count_good += 1
        else:
            count_vulnerable += 1
        if report['dmarc']['valid'] is True:
            count_good += 1
        else:
            count_vulnerable += 1
        if report['dnssec']['enabled'] is True:
            count_good += 1
        else:
            count_vulnerable += 1

    report['good'] = count_good
    report['vulnerable'] = count_vulnerable

    # Generate pie chart
    try:
        data = {'Good': count_good, 'Vulnerable': count_vulnerable}
        labels = [key for key, value in data.items() if value != 0]
        sizes = [value for value in data.values() if value != 0]
        colors = ['green', 'red']
        plt.figure(figsize=(4, 4))
        plt.pie(sizes, labels=labels, labeldistance=0.3, colors=colors, autopct=None,
                startangle=90, shadow=False)
        plt.axis('equal')

        # Save the chart as a PNG image
        buffer = BytesIO()
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        image_png = buffer.getvalue()
        buffer.close()
        image_base64 = base64.b64encode(image_png).decode('utf-8')
        report['img'] = image_base64
    except ValueError as e:
        pass

    template = get_template("pdf_wrapper.html")
    report['site'] = site
    report['test'] = test

    html_out = template.render(report)
    pdf_file = weasyprint.HTML(string=html_out).write_pdf(stylesheets=[weasyprint.CSS(string=css_content)])

    response = HttpResponse(pdf_file, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="tp_{test}_{site}_report.pdf"'
    return response


def url_test(request):
    lookyloo = Lookyloo('https://lookyloo.circl.lu')
    if request.method == 'POST':
        url = request.POST.get('target')
        if lookyloo.is_up:
            context = {'lookyloo_status': lookyloo.is_up}
            capture_uuid = lookyloo.submit(url=url, quiet=True)
            while lookyloo.get_status(capture_uuid)['status_code'] != 1:
                if lookyloo.get_status(capture_uuid)['status_code'] == -1:
                    context['error'] = 'Lookyloo has encountered an issue with the requested capture. Please try again.'
                sleep(5)
            capture = get_capture_result(lookyloo, capture_uuid)
            context['capture'] = capture
            screenshot_stream = lookyloo.get_screenshot(capture_uuid)
            screenshot = base64.b64encode(screenshot_stream.read()).decode('utf-8')
            context['screenshot'] = screenshot
            return render(request, 'check_lookyloo.html', context)
    else:
        recent_captures = get_recent_captures(lookyloo)
        print(recent_captures)
        return render(request, 'check_lookyloo.html', {'recent_captures': recent_captures})
    return render(request, 'check_lookyloo.html')
