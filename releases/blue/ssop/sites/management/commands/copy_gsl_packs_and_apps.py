# https://stackoverflow.com/questions/19475955/using-django-models-in-external-python-script
from django.core.management.base import BaseCommand
import secrets

class Command(BaseCommand):
    help = "generates a random token of a given length; default=64"

    def add_arguments(self, parser):
        parser.add_argument('len', type=int)

    def handle(self, *args, **options):

        tokenlen = options['len']
        token = secrets.token_urlsafe(tokenlen)
        print(token)


