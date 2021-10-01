from django.shortcuts import render, redirect
from django.http import HttpResponseRedirect
from django.contrib.auth.decorators import login_required

from .forms import AnalysisRequestForm
from .models import AnalysisRequest

from decouple import config
from iot_inspector_client import FirmwareMetadata
from datetime import date

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
            return redirect('index')
    else:
        form = AnalysisRequestForm()
    return render(request, 'iot_request.html', {'form': form})
