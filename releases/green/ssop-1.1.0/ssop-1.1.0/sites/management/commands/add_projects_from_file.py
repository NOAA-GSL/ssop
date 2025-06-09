# https://stackoverflow.com/questions/19475955/using-django-models-in-external-python-script
from django.core.management.base import BaseCommand
from sites.models import get_or_add_project
import json
import ast

class Command(BaseCommand):
    help = "Adds all projects found in filename"

    def add_arguments(self, parser):
        parser.add_argument('filename', type=str)

    def handle(self, *args, **options):

        filename = options['filename']
        print('filename: ' + filename)

        fp = open(filename, 'r')
        data = fp.read()
        fp.close
        print('data: ' + str(data))
        projects = json.loads(data)
        print('projects: ' + str(projects))

        for k in projects.keys():
            thisp = {}
            thisp['name'] = str(k)
            for a in projects[k].keys():
                thisp[a] = projects[k][a] 
            print('np = get_or_add_project(' + str(thisp) + ')')
            np = get_or_add_project(thisp)
            print("   np: " + str(np))

