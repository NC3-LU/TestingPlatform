from django_q.models import Schedule, Task


def get_last_runs(tasks):
    last_runs = []
    for task in tasks:
        target = task.target
        scheduled_task = Schedule.objects.get(name=task.schedule.name)
        all_runs = Task.objects.filter(group=scheduled_task.name)
        last_run = all_runs.last()
        for run in all_runs:
            if run.started >= last_run.started:
                last_run = run
        last_runs.append((scheduled_task, target, last_run))
    return last_runs
