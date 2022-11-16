from functools import wraps
from django.contrib import messages
from django.http import HttpResponseRedirect

default_message = "Unauthorised action."


def subscription_required(function):
    @wraps(function)
    def wrap(request, *args, **kwargs):
        user_tier = request.user.tier_level
        if user_tier in (1, 2):
            return function(request, *args, **kwargs)
        else:
            messages.warning(
                request,
                "This feature is limited to subscribed users, please check out our offers in the "
                "dedicated section!",
            )
            return HttpResponseRedirect("/")

    return wrap


def pro_required(function):
    @wraps(function)
    def wrap(request, *args, **kwargs):
        user_tier = request.user.tier_level
        if user_tier == "PRO":
            return function(request, *args, **kwargs)
        else:
            messages.error(request, "Unauthorized access")
            return HttpResponseRedirect("/")

    return wrap


def business_required(function):
    @wraps(function)
    def wrap(request, *args, **kwargs):
        user_tier = request.user.tier_level
        if user_tier == "BUSINESS":
            return function(request, *args, **kwargs)
        else:
            messages.error(request, "Unauthorized access")
            return HttpResponseRedirect("/")

    return wrap
