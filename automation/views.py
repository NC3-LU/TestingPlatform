from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse

from .forms import PingAutomatedTestForm, HttpAutomatedTestForm
from .models import PingAutomatedTest, HttpAutomatedTest
from .helpers import get_last_runs
from testing_platform.decorators import subscription_required

from django_q.models import Task, Schedule


# Create your views here.
@login_required
@subscription_required
def index(request):
    ping_tests = PingAutomatedTest.objects.filter(user=request.user.id)
    ping_list = get_last_runs(ping_tests)
    http_tests = HttpAutomatedTest.objects.filter(user=request.user.id)
    http_list = get_last_runs(http_tests)
    context = {"ping_list": ping_list, "http_list": http_list}
    return render(request, 'automation_index.html', context=context)


@login_required
@subscription_required
def schedule_ping(request):
    if request.method == 'POST':
        form = PingAutomatedTestForm(request.user, request.POST)
        if form.is_valid():
            data = form.cleaned_data
            automation_request = PingAutomatedTest(
                user=request.user,
                target=data['target'],
                frequency=data['frequency'],
                time=data['time'],
                weekday=data['weekday'],
                monthly_test_date=data['monthly_test_date'],
            )
            automation_request.save()
            return redirect('automation')
        else:
            messages.error(request, 'There was an error, please try again')
            return redirect('schedule_ping')
    else:
        form = PingAutomatedTestForm(request.user)
    return render(request, 'automation_request.html', {'form': form, 'title': 'ping test'})


@login_required
@subscription_required
def display_ping_report(request, domain):
    last_run = Task.objects.filter(func='automation.tasks.ping').filter(args=(domain,)).latest('started')
    print(last_run.result['result'])
    return render(request, 'automated_ping_report.html', {'result': last_run.result['result']})


@login_required
@subscription_required
def remove_ping(request, domain):
    ping_automated_test = PingAutomatedTest.objects.get(target__domain=domain)
    if request.user == ping_automated_test.user:
        scheduled_pings = Schedule.objects.filter(func='automation.tasks.ping').filter(args=f"'{domain}'")
        ping_tasks = Task.objects.filter(func='automation.tasks.ping').filter(args=(domain,))
        for item in scheduled_pings:
            item.delete()
        for item in ping_tasks:
            item.delete()
        ping_automated_test.delete()
        return redirect('automation')
    else:
        return HttpResponse(status=401)


@login_required
@subscription_required
def schedule_http(request):
    if request.method == 'POST':
        form = HttpAutomatedTestForm(request.user, request.POST)
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
            return redirect('automation')
        else:
            messages.error(request, 'There was an error, please try again')
            return redirect('schedule_http')
    else:
        form = HttpAutomatedTestForm(request.user)
    return render(request, 'automation_request.html', {'form': form, 'title': 'http test'})


@login_required
@subscription_required
def display_http_report(request, domain):
    last_run = Task.objects.filter(func='automation.tasks.http').filter(args=(domain,)).latest('started')
    return render(request, 'http_report.html', last_run.result)


@login_required
@subscription_required
def remove_http_report(request, domain):
    http_automated_test = HttpAutomatedTest.objects.get(target__domain=domain)
    if http_automated_test.user == request.user:
        scheduled_http = Schedule.objects.filter(func='automation.tasks.http').filter(args=f"'{domain}'")
        http_tasks = Task.objects.filter(func='automation.tasks.http').filter(args=(domain,))
        for item in scheduled_http:
            item.delete()
        for item in http_tasks:
            item.delete()
        http_automated_test.delete()
        return redirect('automation')
    else:
        return HttpResponse(status=401)