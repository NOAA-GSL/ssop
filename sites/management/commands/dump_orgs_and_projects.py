# https://stackoverflow.com/questions/19475955/using-django-models-in-external-python-script
from django.core.management.base import BaseCommand
from django.utils import timezone

from sites.models import Project, Key, Organization

class Command(BaseCommand):
    help = "Dumps Projects and Organiations in JSON"

    def handle(self, *args, **options):

        allproj = Project.objects.all()
        allkey = Key.objects.all()
        allorg = Organization.objects.all()

        data = {}
        pret = {}
        data["projects"] = pret
        for p in allproj:
            pret[str(p)] = {}
            for (k,v) in p.get_fields():
                pret[str(p)][str(k)] = str(v)
        print("      pret = " + str(pret))

        kret = {}
        data["keys"] = kret
        for v in allkey:
            kret[str(v)] = v.get_key()
        print("      kret = " + str(kret))

        oret = {}
        data["organizations"] = oret
        for o in allorg:
            oret[str(o)] = {}
            for (k,v) in o.get_fields():
                oret[str(o)][str(k)] = v
        print("      oret = " + str(oret))

        data = str(data).replace("'", '"', 1000000)
        now = str(timezone.now())
        now = now[0:19]
        fname = now.replace(' ', '_')
        fname = fname.replace('-', '', 3)
        fname = 'SSOP_' + fname.replace(':', '', 4) + '.json'
        print("wrote " + str(fname))
        fp = open(fname, 'w')
        fp.write(str(data))
        fp.close()
