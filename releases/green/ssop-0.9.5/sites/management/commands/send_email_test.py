# https://stackoverflow.com/questions/19475955/using-django-models-in-external-python-script
from django.core.management.base import BaseCommand
from django.core.mail import send_mail

class Command(BaseCommand):
    help = "Test send_email"

    def handle(self, *args, **options):
        subject = "test from webstage8"
        fromaddr = "noreply.gsl@noaa.gov"
        toaddr = ["kirk.l.holub@noaa.gov"]
        body = "this worked form gsl-webstage8"
        try:
            send_mail(subject, body, fromaddr, toaddr, fail_silently=False)
        except Exception as e:
            print("Exception: " + str(e))

