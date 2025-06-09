"""
Add the NONE email Contact if it does not exits.   This placeholder is required to make the GUI happy.
"""
from __future__ import unicode_literals


# https://stackoverflow.com/questions/19475955/using-django-models-in-external-python-script
from django.core.management.base import BaseCommand

from sites.models import add_none_contact, get_or_add_organization_by_name, add_none_project, add_none_token
from ssop import settings

class Command(BaseCommand):
    help = "adds the NONE email Contact, Organization, and Project if needed"

    def handle(self, *args, **options):
        add_none_contact()
        get_or_add_organization_by_name(settings.NONE_NAME)
        add_none_project()
        add_none_token()
