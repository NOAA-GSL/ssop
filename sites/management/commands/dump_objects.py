# https://stackoverflow.com/questions/19475955/using-django-models-in-external-python-script
from django.core.management.base import BaseCommand
from django.utils import timezone

import ast
import pytz
import os
import filecmp
import json
from typing import Dict
from ssop import settings

from sites.models import About, Attributes, AttributeGroup, Connection, Contact, Key, Organization, Project, Room, Sysadmin

class Command(BaseCommand):
    help = "Dumps objects in JSON"

    def handle(self, *args, **options):

        allabout = About.objects.all()
        allattributes = Attributes.objects.all()
        allattributegroups = AttributeGroup.objects.all()
        allconnection = Connection.objects.all()
        allcontact = Contact.objects.all()
        allkey = Key.objects.all()
        allproj = Project.objects.all()
        allorg = Organization.objects.all()
        allroom = Room.objects.all()

        data = {}
        now = str(timezone.now())
        now = now[0:19]
        now = now.replace(' ', '_')
        now = now.replace('-', '', 3)
        nret = {}
        nret["dumputc"] = str(now).strip()
        data["dumputc"] = "dumputc: " + str(nret).strip()
        #print("      dumputc = " + str(now).strip())

        aret = {}
        data["About"] = aret
        for a in allabout:
            akey = "Version:" + str(a).strip()
            aret[akey] = {}
            for (k,v) in a.get_fields():
                aret[akey][str(k).strip()] = str(v).strip()
        #print("      about = " + str(aret).strip())

        pret = {}
        data["Projects"] = pret
        for p in allproj:
            pkey = "name:" + str(p).strip()
            pret[pkey] = {}
            for (k,v) in p.get_fields():
                if not isinstance(v, str):
                    if isinstance(v, Key):
                        kd = {}
                        for kk, kv in v.get_fields():
                            kd[kk] = str(kv)
                        v = kd 
                    pret[pkey][str(k).strip()] = str(v)
                else:
                    pret[pkey][str(k).strip()] = v
        #print("        " + str(len(pret)) + " projects")

        cret = {}
        data["Contacts"] = cret
        for c in allcontact:
            ckey = "firstname lastname (email):" + str(c).strip()
            cret[ckey] = {}
            for (k,v) in c.get_fields():
                cret[ckey][str(k).strip()] = str(v).strip()
        #print("        " + str(len(cret)) + " contacts")

        kret = {}
        data["Keys"] = kret
        for ak in allkey:
            akkey = "name:" + str(ak).strip()
            kret[str(akkey).strip()] = {}
            for (k,v) in ak.get_fields():
                kret[akkey][str(k).strip()] = str(v).strip()
        #print("        " + str(len(kret)) + " keys")

        oret = {}
        data["Organizations"] = oret
        for o in allorg:
            okey = "name:" + str(o).strip()
            oret[str(okey).strip()] = {}
            for (k,v) in o.get_fields():
                oret[okey][str(k).strip()] = str(v).strip()
        #print("        " + str(len(oret)) + " organizations")

        atret = {}
        data["Attributes"] = atret
        for a in allattributes:
            atkey = "fingerprint:" + str(a).strip()
            atret[str(atkey).strip()] = {}
            for (k,v) in a.get_fields():
                atret[atkey][str(k).strip()] = str(v).strip()
        #print("        " + str(len(atret)) + " attributes")

        agret = {}
        data["AttributeGroups"] = agret
        for a in allattributegroups:
            agkey = "name:" + str(a).strip()
            agret[agkey] = {}
            for (k,v) in a.get_fields():
                agret[agkey][str(k).strip()] = str(v).strip()
        #print("        " + str(len(agret)) + " attributeGroups")

        rmret = {}
        data["Room"] = rmret
        for r in allroom:
            rkey = "number:" + str(r).strip()
            rmret[rkey] = {}
            for (k,v) in r.get_fields():
                rmret[rkey][str(k).strip()] = str(v).strip()
        #print("        " + str(len(rmret)) + " Rooms")

        for dt in data.keys():
            fname = settings.DBDUMP_ROOT + 'SSOPSB_' + now.replace(':', '', 4) + '_' + str(dt) + '.json'
            with open(fname, 'w') as fh:
                json.dump(data[dt], fh)

        #dataout = str(data).replace("'", '"', 10000000)
        #fname = settings.DBDUMP_ROOT + 'SSOPSB_' + now.replace(':', '', 4) + '.json'
        #fp = open(fname, 'w')
        #fp.write(dataout)
        #fp.close()

