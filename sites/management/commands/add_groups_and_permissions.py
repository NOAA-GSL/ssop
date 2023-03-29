"""
Added or updates the ICAM (LDAP) groups and assigns permissions.  'groupnames' much match those in settings.py
"""
from __future__ import unicode_literals


# https://stackoverflow.com/questions/19475955/using-django-models-in-external-python-script
from django.core.management.base import BaseCommand

from sites.models import add_groups_and_permissions


class Command(BaseCommand):
    help = "creates and assigns permissions to all groups"

    def handle(self, *args, **options):
        add_groups_and_permissions("add_groups_and_permissions")
