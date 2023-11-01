from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, HttpResponse
from django.shortcuts import redirect, render

from .forms import FirmwareAnalysisRequestForm
from .helpers import api_login, client_generate_report, client_request_link
from .models import FirmwareAnalysisRequest


# Create your views here.
@login_required
def index(request):
    client = api_login()
    reqs = FirmwareAnalysisRequest.objects.filter(user=request.user.id)
    context = {"requests": reqs}
    return render(request, "onekey_index.html", context=context)


def analysis_request(request):
    if request.method == "POST":
        form = FirmwareAnalysisRequestForm(request.POST, request.FILES)
        if form.is_valid():
            data = form.cleaned_data
            firmware_analysis_request = FirmwareAnalysisRequest(
                user=request.user,
                firmware_name=data["firmware_name"],
                firmware_vendor_name=data["firmware_vendor_name"],
                firmware_product_name=data["firmware_product_name"],
                firmware_file=data["firmware_file"],
            )
            firmware_analysis_request.save()
            messages.success(
                request,
                "Your analysis request was successfully saved, you will receive a pricing offer"
                " in the next few days.",
            )
            return redirect("iot_index")
    else:
        form = FirmwareAnalysisRequestForm()
    return render(request, "iot_request.html", {"form": form})


def generate_report(request, firmware_uuid):
    firmware_analysis_request = FirmwareAnalysisRequest.objects.get(
        firmware_uuid=firmware_uuid
    )
    client = api_login()
    request = client_generate_report(
        client, firmware_uuid, str(firmware_analysis_request.request_nb)
    )
    return redirect("iot_index")


def generate_link(request, report_uuid):
    firmware_analysis_request = FirmwareAnalysisRequest.objects.get(
        report_uuid=report_uuid
    )
    client = api_login()
    res = client_request_link(client, report_uuid)
    firmware_analysis_request.report_link = res["downloadUrl"]
    firmware_analysis_request.save()
    return redirect("iot_index")
