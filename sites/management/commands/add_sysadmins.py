# https://stackoverflow.com/questions/19475955/using-django-models-in-external-python-script
from django.core.management.base import BaseCommand
from sites.models import add_sysadmins

class Command(BaseCommand):
    help = "Adds all sysadmins found in settings.SSOP_SYSADS"

    def handle(self, *args, **options):
        creator = "add_sysadmins"

        add_sysadmins(creator)
