from django.contrib import admin
from sites.models import Attributes, AuthToken, Organization, Project, Connection, Uniqueuser, AttributeGroup, GraphNode, NodeType, Key

class AttributesAdmin(admin.ModelAdmin):
    #list_display = ('fingerprint', 'decodedfingerprint', 'clearattrs', 'attrs', 'decodedattrs', 'graph_node_id')
    list_display = ('fingerprint', 'decodedfingerprint', 'clearattrs', 'attrs', 'decodedattrs')
    list_display_links = list_display
    readonly_fields = list_display


class AuthTokenAdmin(admin.ModelAdmin):
    list_display = ('token', 'created', 'expires', 'accessed')
    list_display_links = list_display
    readonly_fields = list_display


class ConnectionAdmin(admin.ModelAdmin):
    #list_display = ('name', 'project', 'requestattrs', 'uniqueuser', 'userattrs', 'token', 'created', 'loggedout')
    list_display = ('name', 'project', 'uniqueuser', 'token', 'created', 'loggedout')
    list_display_links = list_display
    readonly_fields = ('name', 'project', 'uniqueuser', 'token', 'created', 'loggedout', 'attrsgroup', 'connection_state')


class OrganizationAdmin(admin.ModelAdmin):
    #list_display = ('name', 'current_projects', 'contact', 'email', 'graph_node_id')
    list_display = ('name', 'current_projects', 'contact', 'email')
    list_display_links = list_display
    ordering = ('name',)


class ProjectAdmin(admin.ModelAdmin):
    #list_display = ('name', 'organization', 'enabled', 'expiretokens', 'return_to', 'queryparam', 'error_redirect', 'display_order', 'state', 'decrypt_key', 'graph_node_id')
    list_display = ('name', 'organization', 'enabled', 'expiretokens', 'queryparam', 'return_to', 'error_redirect', 'display_order', 'state', 'decrypt_key')
    list_display_links = list_display
    readonly_fields = ('state', 'updater') 
    ordering = ('display_order', 'organization', 'name')

    #def save_model(self, request, obj, form, change):
    #    # now we can save the object and call super
    #    set_creator_and_updater(self, request, obj, form)
    #    obj.save()
    #    super(NfsExportAdmin, self).save_model(request, obj, form, change)


class UniqueuserAdmin(admin.ModelAdmin):
    #list_display = ('name', 'fingerprint', 'clearnameattrs', 'clearallattrs', 'clearconnattrs', 'attributes', 'connattributes', 'graph_node_id')
    list_display = ('name', 'fingerprint', 'clearnameattrs', 'clearallattrs', 'clearconnattrs', 'attributes', 'connattributes')
    list_display_links = list_display
    # readonly_fields = list_display


class AttributeGroupAdmin(admin.ModelAdmin):
    #list_display = ('name', 'attributes', 'graph_node_id')
    list_display = ('name', 'grouptype', 'attributes')
    list_display_links = list_display
    readonly_fields = list_display


class GraphNodeAdmin(admin.ModelAdmin):
    list_display = ('name', 'nodeid', 'node_type')
    list_display_links = list_display
    #readonly_fields = list_display


class NodeTypeAdmin(admin.ModelAdmin):
    list_display = ('type', 'attrs', 'options')
    list_display_links = list_display


admin.site.register(Attributes, AttributesAdmin)
admin.site.register(AttributeGroup, AttributeGroupAdmin)
admin.site.register(AuthToken, AuthTokenAdmin)
admin.site.register(Connection, ConnectionAdmin)
admin.site.register(GraphNode, GraphNodeAdmin)
admin.site.register(Key)
admin.site.register(Organization, OrganizationAdmin)
admin.site.register(NodeType, NodeTypeAdmin)
admin.site.register(Project, ProjectAdmin)
admin.site.register(Uniqueuser, UniqueuserAdmin)
