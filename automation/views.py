from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required

from .forms import PingAutomatedTestForm, HttpAutomatedTestForm
from .models import PingAutomatedTest, HttpAutomatedTest
from .helpers import get_last_runs

from django_q.models import Task, Schedule


# Create your views here.
@login_required
def index(request):
    ping_tests = PingAutomatedTest.objects.filter(user=request.user.id)
    ping_list = get_last_runs(ping_tests)
    http_tests = HttpAutomatedTest.objects.filter(user=request.user.id)
    http_list = get_last_runs(http_tests)
    context = {"ping_list": ping_list, "http_list": http_list}
    return render(request, 'automation_index.html', context=context)


@login_required
def schedule_ping(request):
    if request.method == 'POST':
        form = PingAutomatedTestForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            automation_request = PingAutomatedTest(
                user=request.user,
                host=data['host'],
                frequency=data['frequency'],
                time=data['time'],
                weekday=data['weekday'],
                monthly_test_date=data['monthly_test_date'],
            )
            automation_request.save()
            return redirect('index')
    else:
        form = PingAutomatedTestForm()
    return render(request, 'automation_request.html', {'form': form, 'title': 'ping test'})


@login_required
def schedule_http(request):
    if request.method == 'POST':
        form = HttpAutomatedTestForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            automation_request = HttpAutomatedTest(
                user=request.user,
                target=data['target'],
                frequency=data['frequency'],
                time=data['time'],
                weekday=data['weekday'],
                monthly_test_date=data['monthly_test_date'],
            )
            automation_request.save()
            return redirect('index')
    else:
        form = HttpAutomatedTestForm()
    return render(request, 'automation_request.html', {'form': form, 'title': 'http test'})


@login_required
def display_http_report(request, task_id):
    last_run = Task.objects.filter(group=task_id).latest('started')
    return render(request, 'web_report.html', last_run.result)
