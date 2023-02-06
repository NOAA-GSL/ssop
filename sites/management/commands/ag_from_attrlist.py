# https://stackoverflow.com/questions/19475955/using-django-models-in-external-python-script
from django.core.management.base import BaseCommand
from sites.models import AttributeGroup, Attributes, NodeType, Uniqueuser
from sites.views import test_attributeGroupFromAttributes

class Command(BaseCommand):
    help = "test find attribute group from a list of attributes"


    def handle(self, *args, **options):
        uattributeset = set() 
        cattributeset = set() 
        alluu = Uniqueuser.objects.all()
        numuu = len(alluu)
        print("found " + str(numuu) + " unique users")
        for uu in alluu:
            print("  uu = " + str(uu))
            for a in uu.nameattrsgroup.get_attrs():
                print("     na = " + str(a) + " -- " + str(a.clearattrs()) )
                uattributeset.add(a)
            for a in uu.connattrsgroup.get_attrs():
                print("     ca = " + str(a) + " -- " + str(a.clearattrs()) )
                cattributeset.add(a)

        uattributelist = [] 
        for a in uattributeset:
            uattributelist.append(a)
        cattributelist = [] 
        for a in cattributeset:
            cattributelist.append(a)

        allag = AttributeGroup.objects.all()
        numag = len(allag)
        print("\nfound " + str(numag) + " attribute groups:")
        for ag in AttributeGroup.objects.all():
            print("   ag = " + str(ag))
            for a in ag.attrs.all():
                print("       aga = " + str(a) + " -- " + str(a.clearattrs()) )

        print("\nuattributelist = " + str(uattributelist))
        for a in uattributelist: 
            print("      a = " + str(a) + " -- " + str(a.clearattrs()) )
        print("\ncattributelist = " + str(cattributelist))
        for a in cattributelist: 
            print("      a = " + str(a) + " -- " + str(a.clearattrs()) )

        uaqs = Attributes.objects.filter(attrs__in=uattributelist)
        namegrouptype = NodeType.objects.filter(type='Namegroup').first()
        uattrgroup = test_attributeGroupFromAttributes(namegrouptype, uaqs)
        print("\n   user attribute group: " + str(uattrgroup))

        caqs = Attributes.objects.filter(attrs__in=cattributelist)
        conngrouptype = NodeType.objects.filter(type='Conngroup').first()
        cattrgroup = test_attributeGroupFromAttributes(conngrouptype, caqs)
        print("\n   connection attribute group: " + str(cattrgroup))

