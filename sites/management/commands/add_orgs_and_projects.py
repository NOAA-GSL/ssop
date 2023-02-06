# https://stackoverflow.com/questions/19475955/using-django-models-in-external-python-script
from django.core.management.base import BaseCommand
from sites.models import get_or_add_project
import json
import ast

class Command(BaseCommand):
    help = "Adds all Organizations, Keys, and Projects found in the file created by dump_orgs_and_projects.py"

    def add_arguments(self, parser):
        parser.add_argument('filename', type=str)

    def handle(self, *args, **options):

        filename = options['filename']
        print('filename: ' + filename)

        fp = open(filename, 'r')
        datastr = fp.read()
        fp.close
        #print('datastr: ' + str(datastr))

        data = json.loads(datastr)
        #print('data: ' + str(data))

        for p in data.keys():
            print("   project: " + str(p))
        #    thisp = {}
        #    thisp['name'] = str(k)
        #    for a in projects[k].keys():
        #        thisp[a] = projects[k][a] 
        #    print('np = get_or_add_project(' + str(thisp) + ')')
        #    np = get_or_add_project(thisp)
        #    print("   np: " + str(np))

