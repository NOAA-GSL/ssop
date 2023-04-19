# https://stackoverflow.com/questions/19475955/using-django-models-in-external-python-script
from django.core.management.base import BaseCommand
from sites.models import OrganizationNode, get_or_add_project, get_or_add_organization_by_name
from ssop import settings

class Command(BaseCommand):
    help = "Adds all Organization and Organizations based on settings.ALL_ORGS_BY_ID"


    def handle(self, *args, **options):
        for id in settings.ALL_ORGS_BY_ID.keys():
            org = get_or_add_organization_by_name(settings.ALL_ORGS_BY_ID[id]['name'])
            org.email = settings.ALL_ORGS_BY_ID[id]['email']
            org.contact = settings.ALL_ORGS_BY_ID[id]['contact']
            org.save()


        for id in settings.ALL_ORGS_BY_ID.keys():
            porg = get_or_add_organization_by_name(settings.ALL_ORGS_BY_ID[id]['parent'])
            if settings.NONE_NAME in str(porg):
                continue

            for cid in settings.ALL_ORGS_BY_ID.keys():
                corg = get_or_add_organization_by_name(settings.ALL_ORGS_BY_ID[cid]['name'])
                if porg != corg:
                    print("adding " + str(corg) + " to " + str(porg))
                    #OrganizationNode.objects.create(parent=porg, child=corg)
           
