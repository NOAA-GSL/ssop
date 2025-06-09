"""
Add the NONE email Contact if it does not exits.   This placeholder is required to make the GUI happy.
"""
from __future__ import unicode_literals


# https://stackoverflow.com/questions/19475955/using-django-models-in-external-python-script
from django.core.management.base import BaseCommand

from sites.models import Contact


class Command(BaseCommand):
    help = "add the NONE email Contact if needed"

    def handle(self, *args, **options):
        for c in Contact.objects.all():
            print("  saving " + str(c))
            c.save()
