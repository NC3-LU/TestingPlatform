from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import redirect
from django.shortcuts import render

from .forms import AnalysisRequestForm
from .helpers import api_get_report
from .helpers import client_get_all_reports_states
from .helpers import client_login
from .models import AnalysisRequest
from .models import IOTUser


@login_required
def index(request):
    try:
        if IOTUser.objects.get(user=request.user).activated:
            client = client_login(request.user.iotuser)
            reqs = AnalysisRequest.objects.filter(user=request.user.id)
            all_requests = client_get_all_reports_states(client, reqs)
            context = {"requests": all_requests}
            return render(request, "iot_index.html", context=context)
    except IOTUser.DoesNotExist:
        pass
    except Exception:
        pass
    return render(request, "iot_index.html")


@login_required
def analysis_request(request):
    if request.method == "POST":
        form = AnalysisRequestForm(request.POST, request.FILES)
        if "tos" not in request.POST:
            messages.error(
                request,
                "Please read and accept the terms and conditions of the service before proceeding.",
            )
            return render(request, "iot_request.html", {"form": form})
        if form.is_valid():
            data = form.cleaned_data
            a_request = AnalysisRequest(
                user=request.user,
                name=data["name"],
                vendor_name=data["vendor_name"],
                product_name=data["product_name"],
                file=data["file"],
            )
            a_request.save()
            messages.success(
                request,
                "Your analysis request was successfully saved, you will receive a pricing offer"
                " in the next few days.",
            )
            return redirect("iot_index")
    else:
        form = AnalysisRequestForm()
    return render(request, "iot_request.html", {"form": form})


@login_required
def download_report(request, firmware_uuid):
    a_req = AnalysisRequest.objects.get(firmware_uuid=firmware_uuid)
    req = api_get_report(request.user, str(a_req.report_uuid))
    file = req.content
    response = HttpResponse(
        file,
        headers={
            "Content-Type": "application/pdf",
            "Content-Disposition": f"attachment; "
            f'filename="'
            f'{request.user.company_name}_{firmware_uuid[-12:]}_{str(a_req.report_uuid)[-12:]}.pdf"',
        },
    )
    return response
