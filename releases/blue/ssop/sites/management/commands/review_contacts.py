"""
Add the NONE email Contact if it does not exits.   This placeholder is required to make the GUI happy.
"""
from __future__ import unicode_literals


# https://stackoverflow.com/questions/19475955/using-django-models-in-external-python-script
from django.core.management.base import BaseCommand

from sites.models import review_contacts


class Command(BaseCommand):
    help = "Reviews last connection time of all Contacts and sends a notice"

    def handle(self, *args, **options):
        review_contacts()
