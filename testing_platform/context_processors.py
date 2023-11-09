from testing_platform import tools


def get_version(request):
    """
    Context proprocessor used to render the version of the sowftware
    in the HTML template.
    """
    return tools.get_version()
