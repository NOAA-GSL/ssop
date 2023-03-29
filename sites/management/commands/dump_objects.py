# https://stackoverflow.com/questions/19475955/using-django-models-in-external-python-script
from django.core.management.base import BaseCommand
from django.utils import timezone

import pytz

from ssop import settings

from sites.models import About, Attributes, AttributeGroup, Connection, Key, Organization, Project
#, Uniqueuser

class Command(BaseCommand):
    help = "Dumps objects in JSON"

    def handle(self, *args, **options):

        allabout = About.objects.all()
        allattributes = Attributes.objects.all()
        allattributegroups = AttributeGroup.objects.all()
        allconnection = Connection.objects.all()
        allkey = Key.objects.all()
        allproj = Project.objects.all()
        allorg = Organization.objects.all()
        #alluu = UniqueUser.objects.all()

        data = {}
        now = str(timezone.now())
        now = now[0:19]
        now = now.replace(' ', '_')
        now = now.replace('-', '', 3)
        data["dumputc"] = now 
        print("      dumputc = " + str(now))

        aret = {}
        data["about"] = aret
        for a in allabout:
            aret[str(a)] = {}
            for (k,v) in a.get_fields():
                aret[str(a)][str(k)] = v
        print("      about = " + str(aret))

        pret = {}
        data["projects"] = pret
        for p in allproj:
            pret[str(p)] = {}
            for (k,v) in p.get_fields():
                pret[str(p)][str(k)] = str(v)
        print("        " + str(len(pret)) + " projects")

        kret = {}
        data["keys"] = kret
        for v in allkey:
            kret[str(v)] = v.get_key()
        print("        " + str(len(kret)) + " keys")

        oret = {}
        data["organizations"] = oret
        for o in allorg:
            oret[str(o)] = {}
            for (k,v) in o.get_fields():
                oret[str(o)][str(k)] = v
        print("        " + str(len(oret)) + " organizations")

        atret = {}
        data["attributes"] = atret
        for a in allattributes:
            atret[str(a)] = {}
            for (k,v) in a.get_fields():
                atret[str(a)][str(k)] = v
        print("        " + str(len(atret)) + " attributes")

        agret = {}
        data["attributeGroups"] = agret
        for a in allattributegroups:
            agret[str(a)] = {}
            for (k,v) in a.get_fields():
                agret[str(a)][str(k)] = v
        print("        " + str(len(agret)) + " attributeGroups")

        data = str(data).replace("'", '"', 1000000)

        fname = settings.DBDUMP_ROOT + 'SSOPSB_' + now.replace(':', '', 4) + '.json'
        fp = open(fname, 'w')
        fp.write(str(data))
        fp.close()
        print("wrote " + str(fname))

