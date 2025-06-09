"""
Add a list of ontacts if they do not exits.   This placeholder is required to make the GUI happy.
"""
from __future__ import unicode_literals


# https://stackoverflow.com/questions/19475955/using-django-models-in-external-python-script
from django.core.management.base import BaseCommand

from sites.models import add_contacts_list

class Command(BaseCommand):
    help = "adds a list of Contacts from a list of email, fistname, lastname"

    def add_arguments(self, parser):
        parser.add_argument('filename', type=str)

    def handle(self, *args, **options):

        filename = options['filename']
        print('filename: ' + filename)

        fp = open(filename, 'r')
        userlist = fp.read()
        fp.close
        add_contacts_list(userlist)

