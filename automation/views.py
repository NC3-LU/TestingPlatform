from django.shortcuts import render, redirect
from .forms import PingAutomatedTestForm
from .models import PingAutomatedTest


# Create your views here.
def index(request):
    context = {'automated_tests': PingAutomatedTest.objects.filter(user=request.user.id)}
    return render(request, 'automation_index.html', context=context)


def schedule_test(request):
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
    return render(request, 'automation_request.html', {'form': form})
