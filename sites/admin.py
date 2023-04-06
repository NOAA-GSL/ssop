from django.contrib import admin
from sites.models import About, Attributes, AuthToken, Organization, OrganizationNode, Project, Connection, Uniqueuser, AttributeGroup, GraphNode, NodeType, Key, Sysadmin
from sites.forms import SysadminAdminForm

        
def set_dbfield_to_sysad(fieldname, field, db_field, request):
    if fieldname in str(db_field):
        now = datetime.datetime.utcnow()
        msg = str(now) + ':' + fieldname + ':' + str(db_field) + ":" + get_sysad(request)
        logger.info(msg)
        sysadmin = Sysadmin.objects.filter(username=request.user)
        if sysadmin.count() > 0:
            field.initial = str(sysadmin[0])
    return field

    
class AboutAdmin(admin.ModelAdmin):
    list_display = ('version', 'updated_mst')
    list_display_links = list_display
    readonly_fields = ('version', 'updated_mst', 'requirements')

class AttributesAdmin(admin.ModelAdmin):
    #list_display = ('fingerprint', 'decodedfingerprint', 'clearattrs', 'attrs', 'decodedattrs', 'graph_node_id')
    list_display = ('fingerprint', 'decodedfingerprint', 'decodedattrs', 'attrs')
    list_display_links = list_display
    #readonly_fields = list_display


class AuthTokenAdmin(admin.ModelAdmin):
    list_display = ('token', 'created', 'expires', 'accessed')
    list_display_links = list_display
    readonly_fields = list_display


class ConnectionAdmin(admin.ModelAdmin):
    #list_display = ('name', 'project', 'requestattrs', 'uniqueuser', 'userattrs', 'token', 'created', 'loggedout')
    list_display = ('name', 'project', 'uniqueuser', 'token', 'created', 'loggedout')
    list_display_links = list_display
    readonly_fields = ('name', 'project', 'uniqueuser', 'token', 'created', 'loggedout', 'attrsgroup', 'connection_state')


class OrganizationNodeAdmin(admin.ModelAdmin):
    #list_display = ('name', 'current_projects', 'contact', 'email', 'graph_node_id')
    list_display = ( 'name', 'leaf' )
    list_display_links = list_display

class OrganizationAdmin(admin.ModelAdmin):
    #list_display = ('name', 'current_projects', 'contact', 'email', 'graph_node_id')
    list_display = ('name', 'current_projects', 'contact', 'email')
    list_display_links = list_display
    ordering = ('name',)


class ProjectAdmin(admin.ModelAdmin):
    #list_display = ('name', 'organization', 'enabled', 'expiretokens', 'return_to', 'queryparam', 'error_redirect', 'display_order', 'state', 'decrypt_key', 'graph_node_id')
    list_display = ('name', 'organization', 'enabled', 'expiretokens', 'queryparam', 'return_to', 'error_redirect', 'logoimg', 'showlogobin', 'display_order', 'state', 'decrypt_key')
    list_display_links = list_display
    readonly_fields = ('state', 'updater') 
    ordering = ('display_order', 'organization', 'name')


class SysadminAdmin(admin.ModelAdmin):
    list_display = ('username', 'organization', 'organizations_list')
    list_display_links = list_display
    form = SysadminAdminForm
                
    def formfield_for_dbfield(self, db_field, request, **kwargs):
        field = super(SysadminAdmin, self).formfield_for_dbfield(db_field, request, **kwargs)
        field = set_dbfield_to_sysad('provision.Sysadmin.updater', field, db_field, request)
        return field


class UniqueuserAdmin(admin.ModelAdmin):
    #list_display = ('name', 'fingerprint', 'clearnameattrs', 'clearallattrs', 'clearconnattrs', 'attributes', 'connattributes', 'graph_node_id')
    list_display = ('name', 'fingerprint', 'clearnameattrs', 'clearallattrs', 'clearconnattrs', 'attributes', 'connattributes')
    list_display_links = list_display
    # readonly_fields = list_display


class AttributeGroupAdmin(admin.ModelAdmin):
    #list_display = ('name', 'attributes', 'graph_node_id')
    list_display = ('name', 'grouptype', 'clearattrs', 'attributes')
    list_display_links = list_display
    readonly_fields = list_display


class GraphNodeAdmin(admin.ModelAdmin):
    list_display = ('name', 'nodeid', 'node_type')
    list_display_links = list_display
    #readonly_fields = list_display


class NodeTypeAdmin(admin.ModelAdmin):
    list_display = ('type', 'attrs', 'options')
    list_display_links = list_display


admin.site.register(About, AboutAdmin)
admin.site.register(Attributes, AttributesAdmin)
admin.site.register(AttributeGroup, AttributeGroupAdmin)
admin.site.register(AuthToken, AuthTokenAdmin)
admin.site.register(Connection, ConnectionAdmin)
admin.site.register(GraphNode, GraphNodeAdmin)
admin.site.register(Key)
admin.site.register(OrganizationNode, OrganizationNodeAdmin)
admin.site.register(Organization, OrganizationAdmin)
admin.site.register(NodeType, NodeTypeAdmin)
admin.site.register(Project, ProjectAdmin)
admin.site.register(Sysadmin, SysadminAdmin)
admin.site.register(Uniqueuser, UniqueuserAdmin)
