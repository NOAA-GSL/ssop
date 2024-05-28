# https://stackoverflow.com/questions/19475955/using-django-models-in-external-python-script
from django.core.management.base import BaseCommand
from django.utils import timezone

import ast
import pytz
import os
import re 
import json

from ssop import settings

from sites.models import About, Attributes, AttributeGroup, Connection, Contact, Key, Organization, Project, Room, Sysadmin, get_or_add_organization_by_name, \
                         get_or_add_decrypt_key, get_or_add_contact, get_or_add_group

class Command(BaseCommand):
    help = "Loads objects from JSON dump files"

    astret = ""

    def add_arguments(self, parser):
        parser.add_argument('timestamp', type=str)

    def load_About(self):
        for ak in self.astret.keys():
            #print("ak: " + str(ak))
            version = str(ak).split(':')[1]
            qs = About.objects.filter(Version=version)
            print(str(version) + ":  qs.count() = " + str(qs.count()))
            if qs.count() != int(1):
                na = About(Version=version, Requirements=self.astret[ak]["Requirements"], updated=self.astret[ak]["updated"])
                na.save()
                print("  created: " + str(na))

    def load_Keys(self):
        for kk in self.astret.keys():
            #print("kk: " + str(kk))
            name = str(kk).split(':')[1]
            ak = get_or_add_decrypte_key(keyname=name, dk=self.astret[kk]["decrypt_key"])
            print("  Key: " + str(ak))

    def load_Organizations(self):
        for ok in self.astret.keys():
            #print(" org key: " + str(ok))
            name = str(ok).split(':')[1]
            print(str(name) + ":  qs.count() = " + str(qs.count()))
            org = get_or_add_organization_by_name(name)
            print("  org: " + str(org))

    def load_Contacts(self):
        for ck in self.astret.keys():
            #print("ck: " + str(ck))
            # 'firstname lastname (email)', 'Jen Gardner (jen.gardner@noaa.gov)')
            (firstname, lastname, email) = str(ck).split(':')[1].split(' ')
            email = email.replace('(', '')
            email = email.replace(')', '')
            contact = get_or_add_contact(email=email, firstname=firstname, lastname=lastname)
            print("  contact: " + str(contact))

    def load_Projects(self):
        for pk in self.astret.keys():
            #print("pk " + str(pk))
            name = str(pk).split(':')[1]
            qs = Project.objects.filter(name=name)
            if qs.count() != int(1):
                org = get_or_add_organization_by_name(self.astret[pk]['organization'])
                kd = ast.literal_eval(self.astret[pk]["decrypt_key"])
                decrypt_key = get_or_add_decrypt_key(keyname=kd['name'], dk=kd['decrypt_key'])
                verbose_name = self.astret[pk]["verbose_name"]
                return_to = self.astret[pk]["return_to"]
                owner = str(self.astret[pk]["owner"])
                none = str(settings.NONE_NAME).replace("#", "")
                if none in owner:
                    owner = get_or_add_contact(email=settings.NONE_EMAIL)
                else:
                    (firstname, lastname, email) = str(self.astret[pk]["owner"]).split(" ")
                    email = email.replace("(", "")
                    email = email.replace(")", "")
                    owner = get_or_add_contact(email=email, firstname=firstname, lastname=lastname)
                queryparam = self.astret[pk]["queryparam"]
                querydelimiter = self.astret[pk]["querydelimiter"]
                error_redirect = self.astret[pk]["error_redirect"]
                state = self.astret[pk]["state"]
                enabled = self.astret[pk]["enabled"]
                expiretokens = self.astret[pk]["expiretokens"]
                display_order = self.astret[pk]["display_order"]
                logoimg = self.astret[pk]["logoimg"]
                app_params = self.astret[pk]["app_params"]
                userslist = self.astret[pk]["userslist"]
                np = Project(name=name, organization=org, verbose_name=verbose_name, return_to=return_to, \
                             queryparam=queryparam, querydelimiter=querydelimiter, error_redirect=error_redirect, \
                             state=state, enabled=enabled, expiretokens=expiretokens, display_order=display_order, \
                             logoimg = logoimg, app_params=app_params, decrypt_key=decrypt_key, owner=owner)
                np.save()
                print("  created: " + str(np))

                for user in userslist.split(','):
                    #print("   attempting to add user: " + str(user))
                    if not '@' in user:
                       continue
                    (firstname, lastname, email) = user.split(" ")
                    email = email.replace("(", "")
                    email = email.replace(")", "")
                    ac = get_or_add_contact(email=email, firstname=firstname, lastname=lastname)

                # fields added since last release
                try:
                     pfishing_resistant= self.astret[pk]["pfishing_resistant"]
                     idp = self.astret[pk]["idp"]
                     groups = self.astret[pk]["groupslist"]
                     np.pfishing_resistant = pfishing_resistant
                     np.idp = idp
                     for g in groups.split(':'):
                         if str(g).startswith('cn='):
                             ng = get_or_add_group(name=g)
                             np.groups.add(ng)
                     np.save()
                except KeyError as ke:
                     print("  exception: " + str(ke))

    def load_Rooms(self):
        for room in self.astret.keys():
            print("room: " + str(room))
            number = str(room).split(':')[1]
            qs = Room.objects.filter(number=number)
            if qs.count() != int(1):
                name = self.astret[room]["name"]
                state = self.astret[room]["current_state"]
                nr = Room(number=number, name=name, current_state=state)
                nr.save()
                print("  new room: " + str(nr))

    def handle(self, *args, **options):

        timestamp = options['timestamp']

        #objtypes = ["About", "Contact", "Key", "Organization", "Room", "Project"]
        objtypes = ["Room"]
        filelist = []
        for fn in os.listdir(settings.DBDUMP_ROOT):
            if timestamp in fn:
                filelist.append(fn)

        fnbytype = {} 
        for fn in filelist:
            for ot in objtypes:
                if str(ot) in str(fn):
                   fnbytype[ot] = str(fn)
                   continue 

        for k in objtypes:
            fh = open(fnbytype[k], "r")
            jsonobj= json.load(fh)
            fh.close()

            self.astret = ast.literal_eval(str(jsonobj))

            if "About" in str(k):
                self.load_About()

            if "Key" in str(k):
                self.load_Keys()

            if "Contact" in str(k):
                self.load_Contacts()

            if "Project" in str(k):
                self.load_Projects()

            if "Room" in str(k):
                self.load_Rooms()

