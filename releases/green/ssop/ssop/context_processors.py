"""
A set of request processors that return dictionaries to be merged into a
template context. Each function takes the request object as its only parameter
and returns a dictionary to add to the context.

These are referenced from the 'context_processors' option of the configuration
of a DjangoTemplates backend and used by RequestContext.
"""
import logging

from ssop import settings

logger = logging.getLogger('ssop.models')

# http://www.aptivate.org/en/blog/2013/01/22/making-it-obvious-which-copy-of-a-django-site-you-are-using/
def deploy_env(request):
    """
    Add the deploy environment so we can show it when useful
    """
    if hasattr(settings, 'SSOP_DEPLOY_ENV'):
        denv = settings.SSOP_DEPLOY_ENV
    else:
        denv = 'Unknown deploy_env for ' + str(request)
    
    extra_context = {'deploy_env': denv}
    if hasattr(settings, 'SSOP_DEPLOY_ENV'):
        extra_context['deploy_env_color'] = settings.DEPLOY_ENV_COLOR
        extra_context['deploy_env_text_color'] = settings.DEPLOY_ENV_TEXT_COLOR

    return extra_context

def server_url(request):
    """
    make the server url available to forms
    """
    if hasattr(settings, 'SERVER_FQDN'):
        server = 'https://' + settings.SERVER_FQDN
    else:
        server = 'Unknown SERVER for ' + str(request)

    extra_context = {'server_url': server}
    return extra_context


def cwd_refresh_rate(request):
    extra_context = {'cwd_refresh_rate': settings.PAGE_REFRESH_RATE}
    return extra_context


def lapse_in_appropriations(request):
    extra_context = {'lapse_in_appropriations': False}
    if settings.LAPSE_IN_APPROPRIATIONS:
        extra_context['lapse_in_appropriations'] = True
        extra_context['lapse_in_appropriations_message_top'] = settings.LAPSE_IN_APPROPRIATIONS_MESSAGE_TOP
        extra_context['lapse_in_appropriations_link'] = settings.LAPSE_IN_APPROPRIATIONS_LINK
        extra_context['lapse_in_appropriations_message_bottom'] = settings.LAPSE_IN_APPROPRIATIONS_MESSAGE_BOTTOM
    return extra_context

