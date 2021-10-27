from django.shortcuts import render, redirect
from django.http import HttpResponseRedirect, HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib import messages

from .forms import AnalysisRequestForm
from .models import AnalysisRequest
from .helpers import api_get_report

from iot_inspector_client import FirmwareMetadata
from datetime import date
import mimetypes

from .helpers import *


@login_required
def index(request):
    context = {"requests": AnalysisRequest.objects.filter(user=request.user.id)}
    return render(request, 'iot_index.html', context=context)


@login_required
def analysis_request(request):
    if request.method == 'POST':
        form = AnalysisRequestForm(request.POST, request.FILES)
        if form.is_valid():
            data = form.cleaned_data
            a_request = AnalysisRequest(
                user=request.user,
                name=data['name'],
                vendor_name=data['vendor_name'],
                product_name=data['product_name'],
                file=data['file'],
            )
            a_request.save()
            messages.success(request, 'Your analysis request was successfully saved, you will receive a pricing offer'
                                      ' in the next few days.')
            return redirect('iot_index')
    else:
        form = AnalysisRequestForm()
    return render(request, 'iot_request.html', {'form': form})


@login_required
def download_report(request, firmware_uuid):
    client = client_login(request.user.iotuser)
    a_req = AnalysisRequest.objects.get(firmware_uuid=firmware_uuid)
    req = api_get_report(request.user, str(a_req.report_uuid))
    file = req.content
    response = HttpResponse(file, headers={
        'Content-Type': 'application/pdf',
        'Content-Disposition': f'attachment; '
                               f'filename="'
                               f'{request.user.company_name}_{firmware_uuid[-12:]}_{str(a_req.report_uuid)[-12:]}.pdf"'
    })
    return response
