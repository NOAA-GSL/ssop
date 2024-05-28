"""
Ensures the default Data Center Rooms have been created
"""
from __future__ import unicode_literals


# https://stackoverflow.com/questions/19475955/using-django-models-in-external-python-script
from django.core.management.base import BaseCommand

from sites.models import add_datacenter_rooms
from ssop import settings

class Command(BaseCommand):
    help = "adds data center rooms for the Critical Weather Status page"

    def handle(self, *args, **options):
        add_datacenter_rooms()
