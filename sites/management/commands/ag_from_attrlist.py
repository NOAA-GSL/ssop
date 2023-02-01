# https://stackoverflow.com/questions/19475955/using-django-models-in-external-python-script
from django.core.management.base import BaseCommand
from sites.models import AttributeGroup, NodeType, Uniqueuser
from sites.views import test_attributeGroupFromAttributes

class Command(BaseCommand):
    help = "test find attribute group from a list of attributes"


    def handle(self, *args, **options):
        uattributelist = set() 
        cattributelist = set() 
        for uu in Uniqueuser.objects.all():
            print("uu = " + str(uu))
            for a in uu.nameattrsgroup.get_attrs():
                print("   na = " + str(a) + " -- " + str(a.clearattrs()) )
                uattributelist.add(a)
            for a in uu.connattrsgroup.get_attrs():
                print("   ca = " + str(a) + " -- " + str(a.clearattrs()) )
                cattributelist.add(a)

        for ag in AttributeGroup.objects.all():
            print("\nag = " + str(ag))
            for a in ag.attrs.all():
                print("      a = " + str(a) + " -- " + str(a.clearattrs()) )

        print("\nuattributelist = " + str(uattributelist))
        for a in uattributelist: 
            print("      a = " + str(a) + " -- " + str(a.clearattrs()) )
        print("\ncattributelist = " + str(cattributelist))
        for a in cattributelist: 
            print("      a = " + str(a) + " -- " + str(a.clearattrs()) )

        namegrouptype = NodeType.objects.filter(type='Namegroup').first()
        uattrgroup = test_attributeGroupFromAttributes(namegrouptype, uattributelist)
        print("\n   user attribute group: " + str(uattrgroup))

        conngrouptype = NodeType.objects.filter(type='Conngroup').first()
        cattrgroup = test_attributeGroupFromAttributes(conngrouptype, cattributelist)
        print("\n   connectin attribute group: " + str(cattrgroup))

