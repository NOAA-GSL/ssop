from django.db import models
from django.utils.timezone import now
from django.utils.safestring import mark_safe
from hashlib import md5
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidSignature
import base64

import ast
import datetime
import pytz
import secrets
import logging
import pprint

logger = logging.getLogger('ssop.models')

from ssop import settings

def bytes_in_string(b):
        return str(b)[2:-1]

def get_attributesFromFp(fp):
    fp = str(fp).strip()
    attrs = None
    qs = Attributes.objects.filter(fingerprint=fp)
    if qs.count() == int(1):
        attrs = qs[0].clearattrs()
    else:
        attrs = {}
        for a in qs:
            attrs[str(a)] = a
    return str(attrs)

def get_or_add_organization_by_name(name):
    #name = organization["name"]
    qs = Organization.objects.filter(name=name)
    if qs.count() < int(1):
        #contact = organization["contact"]
        #email = organization["email"]
        #no = Organization(name=name, contact=contact, email=email)
        no = Organization(name=name)
        no.save()
    else:
        no = qs[0]
    return no

def get_or_add_project(project):
    name = project["name"]
    qs = Project.objects.filter(name=name)
    if qs.count() < int(1):
        do = project["display_order"]
        qp = project["queryparam"]
        en = project["enabled"]
        vn = project["verbose_name"]
        og = project["organization"]
        rt = project["return_to"]
        er = project["error_redirect"]
        org = get_or_add_organization_by_name(og)
        key = Key()
        key.save()
        np = Project(name=name, display_order=do, queryparam=qp, enabled=en, verbose_name=vn, organization=org, return_to=rt, error_redirect=er, decrypt_key=key)
        np.save()
    else:
        np = qs[0]
    return np

class Project(models.Model):
    name = models.CharField(max_length=150, default='newproject', help_text=mark_safe(settings.HELP_NAME))
    organization = models.ForeignKey('sites.Organization', null=True, blank=True, on_delete=models.CASCADE, help_text=mark_safe(settings.HELP_ORGANIZATION))
    verbose_name = models.CharField(max_length=150, default='newproject verbose', help_text=mark_safe(settings.HELP_VERBOSE_NAME))
    return_to = models.CharField(max_length=150, default=settings.LOGINDOTGOV_RETURN_TO, help_text=mark_safe(settings.HELP_RETURN_TO))
    queryparam = models.BooleanField(default=True, verbose_name='Token on url', help_text=mark_safe(settings.HELP_QUERYPARAM))
    error_redirect = models.CharField(max_length=150, default=settings.LOGINDOTGOV_ERROR_REDIRECT, help_text=mark_safe(settings.HELP_ERROR_REDIRECT))
    state = models.CharField(max_length=50, null=True, default='setme', help_text=mark_safe(settings.HELP_STATE))
    decrypt_key = models.ForeignKey('sites.Key', null=True, blank=True, on_delete=models.CASCADE, help_text=mark_safe(settings.HELP_DECRYPT_KEY_NAME))
    updated = models.DateTimeField(auto_now_add=True)
    updater = models.CharField(default='None', max_length=200)
    enabled = models.BooleanField(default=False, help_text=mark_safe(settings.HELP_ENABLED))
    expiretokens = models.BooleanField(default=False, help_text=mark_safe(settings.HELP_EXPIRETOKENS))
    display_order = models.IntegerField(default=0, help_text=mark_safe(settings.HELP_DISPLAY_ORDER))
    graphnode = models.ForeignKey('sites.GraphNode', null=True, blank=True, on_delete=models.SET_NULL)

    def __str__(self):
        return self.name

    def graph_node_id(self):
        nid = str(-1)
        if self.graphnode is not None:
            nid = self.graphnode.nid()
        return nid

    def initstate(self):
        need_to_save = False
        state = self.get_state()
        if 'newproject' in self.verbose_name:
            self.verbose_name = self.name 
            need_to_save = True 
        if 'setme' in state:
            self.state = secrets.token_urlsafe(15)
            qs = Project.objects.all()
            self.display_order = qs.count()
            need_to_save = True
        try:
            dk = self.get_decode_key()
            if 'setme' in str(dk):
                dk = Key()
                need_to_save = True 
        except KeyError:
            dk = 0

        if int(self.graph_node_id()) < int(0):
            nt = NodeType.objects.filter(type='Project').first()
            gn = GraphNode(name=self.name, nodetype=nt) 
            gn.save()
            self.graphnode = gn
            need_to_save = True 

        if need_to_save:
            self.save()

    def save(self, *args, **kwargs):
        super(Project, self).save(*args, **kwargs)
        self.initstate()

    def get_returnto(self):
        return self.return_to

    def get_err_redirect(self):
        return self.error_redirect

    def get_state(self):
        return self.state

    def get_verbose_name(self):
        return self.verbose_name

    def get_connection_state(self):
        utcnow = datetime.datetime.utcnow()
        utcnow = utcnow.replace(tzinfo=pytz.UTC)
        return utcnow.strftime('%s') + str(self.get_state())

    def get_decode_key(self):
        key = 'none'
        try:
            if self.decrypt_key is not None:
                sdkey = self.decrypt_key.get_key()
                key = str(sdkey)
        except KeyError:
             pass
        return key

    def is_enabled(self):
        return self.enabled

    def append_access_token(self):
        return self.queryparam


class Attributes(models.Model):
    fingerprint = models.CharField(max_length=150, default='setme')
    decodedfingerprint = models.CharField(max_length=150, default='setme')
    attrs = models.TextField(default='')
    decodedattrs = models.TextField(default='setme')
    #graphnode = models.ForeignKey('sites.GraphNode', null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        verbose_name_plural = 'Attributes'

    def __str__(self):
        return self.fingerprint

    #def graph_node_id(self):
    #    nid = str(-1)
    #    if self.graphnode is not None:
    #        nid = self.graphnode.nid()
    #    return nid
 
    def initstate(self):
        need_to_save = False 
        if 'setme' in str(self.fingerprint):
            attrs = self.get_attributes()
            self.fingerprint = md5(attrs).hexdigest()
            if settings.DEBUG:
                fernet = Fernet(settings.DATA_AT_REST_KEY_ATTRS)
                self.decodedattrs = fernet.decrypt(self.attrs).decode()
            else:
                self.decodedattrs = "Decoded attributes not available."
            self.save()
            need_to_save = True 
        #if int(self.graph_node_id()) < int(0):
        #    nt = NodeType.objects.filter(type='Attribute').first()
        #    gn = GraphNode(name=self.fingerprint, nodetype=nt) 
        #    gn.save()
        #    self.graphnode = gn
        #    need_to_save = True
        return need_to_save 


    def save(self, *args, **kwargs):
        super(Attributes, self).save(*args, **kwargs)
        if self.initstate():
            super(Attributes, self).save(*args, **kwargs)


    def get_attributes(self):
        return self.attrs

    def clearattrs(self):
        return self.decodedattrs 


class AuthToken(models.Model):
    token = models.CharField(max_length=150, default='setme')
    created = models.DateTimeField(auto_now_add=True)
    accessed = models.DateTimeField(default=now)
    expires = models.DateTimeField(default=now)

    def __str__(self):
        return self.token

    def initstate(self):
        need_to_save = False
        if 'setme' in str(self.token):
            self.token = secrets.token_urlsafe(10)
            mindt = datetime.datetime.combine(datetime.date.min, datetime.time.min)
            self.accessed = mindt.replace(tzinfo=pytz.UTC)
            expires = self.created.replace(tzinfo=pytz.UTC)
            self.expires = expires + datetime.timedelta(seconds=settings.ATTRS_ACCESS_TOKEN_LIFETIME)
            need_to_save = True
        return need_to_save

    def save(self, *args, **kwargs):
        super(AuthToken, self).save(*args, **kwargs)
        if self.initstate():
           super(AuthToken, self).save(*args, **kwargs)

    def get_token(self):
        utcnow = datetime.datetime.utcnow()
        utcnow = utcnow.replace(tzinfo=pytz.UTC)
        
        if (utcnow < self.expires):
            self.accessed = utcnow
            mindt = datetime.datetime.combine(datetime.date.min, datetime.time.min)
            self.expires = mindt.replace(tzinfo=pytz.UTC)
            self.save()
            return str(self.token)
        else:
            return str('EXPIRED')


class Connection(models.Model):
    name = models.CharField(max_length=150, default='setme')
    project = models.ForeignKey(Project, null=True, blank=True, on_delete=models.CASCADE)
    attrsgroup = models.ForeignKey('sites.AttributeGroup', null=True, blank=True, on_delete=models.CASCADE, related_name='sites_Connection_attrsgroup')
    uniqueuser = models.ForeignKey('sites.Uniqueuser', null=True, blank=True, on_delete=models.CASCADE, related_name='sites_Connection_uniqueuser', verbose_name='Unique User')
    token = models.ForeignKey(AuthToken, null=True, blank=True, on_delete=models.CASCADE)
    connection_state = models.CharField(max_length=50, null=True, default='setme', help_text=mark_safe(settings.HELP_CONNECTION_STATE))
    created = models.DateTimeField(auto_now_add=True)
    loggedout = models.DateTimeField(default=now)

    def __str__(self):
        return str(self.project) + ' - ' + str(self.created)

    def initstate(self):
        need_to_save = False
        if 'setme' in self.name:
            name = self.get_projectname() + ' - ' + str(self.created)
            self.name = md5(name.encode()).hexdigest()
            self.loggedout = datetime.datetime.combine(datetime.date.min, datetime.time.min)
            need_to_save = True 
        return need_to_save

    def save(self, *args, **kwargs):
        super(Connection, self).save(*args, **kwargs)
        if self.initstate():
            super(Connection, self).save(*args, **kwargs)

    def get_projectname(self):
            return str(self.project)

    def get_uniqueusername(self):
            return str(self.uniqueuser)

    def get_connection_state(self):
            return str(self.connection_state)

    def get_ca(self):
        ca = {} 
        for fp in self.attrsgroup.attributes().split(','):
            at = ast.literal_eval(get_attributesFromFp(fp))
            for k in at.keys(): 
                ca[k] = at[k]
        return ca

    def get_request_attributes(self):
        attributes = []
        #requestattrs = ast.literal_eval(self.requestttrs.get_attributes())
        #attributes.append(('requestattrs: ', str(requestattrs)))
        ca = self.get_ca() 
        attributes.append(('requestattrs: ', str(ca)))
        return attributes

    def get_ua(self):
        ua = {}
        for a in self.uniqueuser.get_attributes():
            attrs = a.get_attributes()
            if len(str(attrs)) > int(9) and str(attrs).startswith('{'):   # minimum str(attrs) == '{"k":"v"}'
                at = ast.literal_eval(a.get_attributes())
                for k in at.keys(): 
                    ua[k] = at[k]
            else:
                ua['simplestring'] = attrs
            neua = str(ua).encode()
            self.fingerprint = md5(neua).hexdigest()
        return ua

    def get_user_attributes(self):
        attributes = []
        #userattrs = ast.literal_eval(self.userattrs.get_attributes())
        #attributes.append(('user_attributes', str(userattrs)))
        ua = self.get_ua()
        attributes.append(('user_attributes', str(ua)))
        return attributes

    def show_user_attributes(self):
        fernet = Fernet(settings.DATA_AT_REST_KEY_ATTRS)
        ua = self.get_ua()
        dataatrest = bytes_in_string(ua['simplestring'])
        decoded_attrs = fernet.decrypt(dataatrest).decode()

        attributes = []
        ale = ast.literal_eval(decoded_attrs)
        msg = "  show_user_attributes ale: " + str(ale)
        logger.info(msg)

        for k in ale.keys():
            attributes.append((str(k), ale[k]))
        attributes.append(('data at rest', str(attributes)))
        return attributes

    def show_request_attributes(self):
        fernet = Fernet(settings.DATA_AT_REST_KEY_ATTRS)
        #attrs = ast.literal_eval(self.requestattrs.get_attributes())
        #decoded_attrs = fernet.decrypt(attrs).decode()
        ca = self.get_ca() 
        decoded_attrs = fernet.decrypt(ca).decode()
        #msg = "  decoded_attrs: " + str(decoded_attrs)
        #logger.info(msg)

        attributes = []
        ale = ast.literal_eval(decoded_attrs)
        #msg = "  ale: " + str(ale)
        #logger.info(msg)

        for k in ale.keys():
            attributes.append((str(k), str(ale[k])))
        attributes.append(('data at rest', str(attrs)))
        return attributes


class Uniqueuser(models.Model):
    name = models.CharField(max_length=150, default='setme')
    fingerprint = models.CharField(max_length=150, default='setme')
    connfingerprint = models.CharField(max_length=150, default='setme')
    nameattrsgroup = models.ForeignKey('sites.AttributeGroup', null=True, blank=True, on_delete=models.CASCADE, related_name='Uniqueuser_nameattrsgroup')
    connattrsgroup = models.ForeignKey('sites.AttributeGroup', null=True, blank=True, on_delete=models.CASCADE, related_name='Uniqueuser_connattrsgroup')
    decodedallattrs = models.TextField(default='setme')
    decodednameattrs = models.TextField(default='setme')
    decodedconnattrs = models.TextField(default='setme')
    created = models.DateTimeField(auto_now_add=True)
    graphnode = models.ForeignKey('sites.GraphNode', null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        verbose_name = "Unique User"

    def __str__(self):
        return self.name

    def graph_node_id(self):
        nid = str(-1)
        if self.graphnode is not None:
            nid = self.graphnode.nid()
        return nid

    def initstate(self):
        need_to_save = False
        if 'setme' in self.name:
            utcnow = datetime.datetime.utcnow()
            yydoy = utcnow.strftime('%y') + utcnow.strftime('%j')
            userstoday = 1
            for uu in Uniqueuser.objects.all():
                if yydoy in str(uu):
                    userstoday = userstoday + 1
            self.name = yydoy + str(userstoday)
            if int(self.graph_node_id()) < int(0):
                nt = NodeType.objects.filter(type='Uniqueuser').first()
                gn = GraphNode(name=self.name, nodetype=nt) 
                gn.save()
                self.graphnode = gn
            need_to_save = True 

        if 'setme' in self.get_fingerprint() or 'setme' in str(self.clearallattrs()):
            da = {}
            uu = {} 
            if self.nameattrsgroup is not None:
                for fp in self.nameattrsgroup.get_attrs():
                    attrs = get_attributesFromFp(str(fp))
                    if len(str(attrs)) > int(9) and str(attrs).startswith('{'):   # minimum str(ca) == '{"k":"v"}'
                        at = ast.literal_eval(attrs)
                        for k in at.keys(): 
                            da[k] = at[k]
                            if 'sub' in str(k) or 'email' in str(k):
                                uu[k] = at[k]
                    else:
                        #da['simplestring'] = []
                        da['simplestring'] = attrs
                if settings.DEBUG:
                    self.decodedallattrs = da
                    self.decodednameattrs = uu 
                else:
                    self.decodedattrs = "Decoded attributes not available."
                    self.decodednameattrs = "Decoded attributes not available."

            msg = "    initstate uu: " + str(uu)
            logger.info(msg)
            enuu = str(uu).encode()
            msg = "    initstate enuu: " + str(enuu)
            logger.info(msg)
            self.fingerprint = md5(enuu).hexdigest()
            msg = "    self.fingerprint: " + str(self.fingerprint)
            logger.info(msg)
            need_to_save = True 

        if 'setme' in self.get_connfingerprint() or 'setme' in str(self.clearconnattrs()):
            ca = {} 
            ca['simplestring'] = [] 
            if self.connattrsgroup is not None:
                for fp in self.connattrsgroup.get_attrs():
                    attrs = get_attributesFromFp(str(fp))
                    if len(str(attrs)) > int(9) and str(attrs).startswith('{'):   # minimum str(ca) == '{"k":"v"}'
                        at = ast.literal_eval(attrs)
                        for k in at.keys(): 
                            ca[k] = at[k]
                    else:
                        ca['simplestring'].append(attrs)
                if settings.DEBUG:
                    self.decodedconnattrs = ca
            enca = str(ca).encode()
            self.connfingerprint = md5(enca).hexdigest()
            need_to_save = True 
        return need_to_save

    def save(self, *args, **kwargs):
        super(Uniqueuser, self).save(*args, **kwargs)
        if self.initstate():
            super(Uniqueuser, self).save(*args, **kwargs)

    def get_fingerprint(self):
        return str(self.fingerprint)

    def get_connfingerprint(self):
        return str(self.connfingerprint)

    def get_attributes(self):
        attrs = {}
        if self.nameattrsgroup is not None:
            attrs = self.nameattrsgroup.get_attrs()
        return attrs

    def clearallattrs(self):
        return self.decodedallattrs 

    def clearnameattrs(self):
        data = self.decodednameattrs 
        pp = pprint.PrettyPrinter()
        return data

    def clearconnattrs(self):
        return self.decodedconnattrs 

    def attributes(self):
        at = ['none']
        if self.nameattrsgroup is not None:
            at = []
            for a in self.nameattrsgroup.attrs.get_queryset():
               at.append(str(a))
        return str(at)

    def connattributes(self):
        at = ['none']
        if self.connattrsgroup is not None:
          if self.connattrsgroup is not None:
              at = []
              for a in self.connattrsgroup.attrs.get_queryset():
                 at.append(str(a))
        return str(at)


class Organization(models.Model):
    name = models.CharField(max_length=50, null=True, default='unknownOrganization')
    contact = models.CharField(max_length=50, null=True, default='unknown Point of Contact')
    email = models.CharField(max_length=50, null=True, default='unknown email')
    projects = models.ManyToManyField(Project, related_name='orgs_projects')
    updated = models.DateTimeField(auto_now_add=True)
    graphnode = models.ForeignKey('sites.GraphNode', null=True, blank=True, on_delete=models.SET_NULL)

    def __str__(self):
        return str(self.name)

    def graph_node_id(self):
        nid = str(-1)
        if self.graphnode is not None:
            nid = self.graphnode.nid()
        return nid

    def current_projects(self):
        cp = []
        for p in Project.objects.all():
            if p.organization == self:
              cp.append(p.name)
        if len(cp) > int(0):
            cp.sort()
        retstr = ''
        for p in cp:
            retstr = retstr + ', ' + str(p)
        return str(retstr[2:])

    def initstate(self):
        need_to_save = False 
        if int(self.graph_node_id()) < int(0):
            nt = NodeType.objects.filter(type='Organization').first()
            gn = GraphNode(name=self.name, nodetype=nt) 
            gn.save()
            self.graphnode = gn
            need_to_save = True 
        return need_to_save

    def save(self, *args, **kwargs):
        super(Organization, self).save(*args, **kwargs)
        if self.initstate():
            super(Organization, self).save(*args, **kwargs)


class AttributeGroup(models.Model):
    name = models.CharField(max_length=150, default='setme')
    grouptype = models.ForeignKey('sites.NodeType', null=True, blank=True, on_delete=models.CASCADE)
    attrs = models.ManyToManyField(Attributes, related_name='AttributeGroup_attrs', verbose_name='Attrs')
    decodedattrs = models.TextField(default='setme')
    #graphnode = models.ForeignKey('sites.GraphNode', null=True, blank=True, on_delete=models.SET_NULL)

    def __str__(self):
        return self.name

    #def graph_node_id(self):
    #    nid = str(-1)
    #    if self.graphnode is not None:
    #        nid = self.graphnode.nid()
    #    return nid

    def initstate(self):
        need_to_save = False 
        if 'setme' in self.name:
            utcnow = datetime.datetime.utcnow().strftime('%s')
            self.name = md5(utcnow.encode()).hexdigest()
            #if int(self.graph_node_id()) < int(0):
            #    nt = NodeType.objects.filter(type='AttributeGroup').first()
            #    gn = GraphNode(name=self.name, nodetype=nt) 
            #    gn.save()
            #    self.graphnode = gn
            need_to_save = True

        if 'setme' in self.decodedattrs:
            if self.attrs is not None:
                dattrs = "Decoded attributes not available."
                if settings.DEBUG:
                    dattrs = ''
                    for a in self.attrs:
                        dattrs = dattrs + a.clearattrs() + ', '
                    dattrs = dattrs[:-2]
                self.decodedattrs = dattrs
                need_to_save = True
        return need_to_save

    def save(self, *args, **kwargs):
        super(AttributeGroup, self).save(*args, **kwargs)
        if self.initstate():
            super(AttributeGroup, self).save(*args, **kwargs)

    def get_attrs(self):
        return self.attrs.get_queryset()

    def attributes(self):
        msg = ''
        for a in self.attrs.get_queryset():
            msg = msg + str(a) + ', '
        if msg.endswith(', '):
            msg =  msg[:-2]
        return msg

    def clearattrs(self):
        return self.decodedattrs 


class GraphNode(models.Model):
    name = models.CharField(max_length=150, default='setme')
    nodeid = models.IntegerField(default='-1')
    nodetype = models.ForeignKey('sites.NodeType', null=True, blank=True, on_delete=models.CASCADE)

    def __str__(self):
        return str(self.name)

    def nid(self):
        return str(self.nodeid)

    def initstate(self):
        need_to_save = False
        if int(self.nodeid) < int(0):
            self.nodeid = self.nextnn() 
            need_to_save = True 
        return need_to_save 

    def save(self, *args, **kwargs):
        super(GraphNode, self).save(*args, **kwargs)
        if self.initstate():
            super(GraphNode, self).save(*args, **kwargs)

    def nextnn(self):
        qs = GraphNode.objects.all()
        return qs.count()

    def node_type(self):
        return str(self.nodetype) 


class NodeType(models.Model):
    type = models.CharField( max_length=20)
    options = models.CharField(max_length=512, default='{}')
    attrs = models.CharField(max_length=512, default='{}')

    def __str__(self):
        return str(self.type)

    def get_options(self):
        return str(self.options)

    def get_attrs(self):
        return str(self.attrs)

#    def save(self, *args, **kwargs):
#        super(NodeType, self).save(*args, **kwargs)


class Browser(models.Model):
    name = models.CharField( max_length=20)
    os = models.CharField(max_length=30, default='unknown')
    version = models.CharField(max_length=512, default='unknown')
    clearattrs = models.CharField(max_length=512, default='')

    def __str__(self):
        return str(self.name)

    def get_os(self):
        return str(self.os)

    def get_version(self):
        return str(self.version)

    def get_attrs(self):
        return str(self.clearattrs)

    def initstate(self):
        need_to_save = False
        if self.get_attrs.startswith('Google Chrome'):
            self.name = 'Google Chrome' 
            attrs = self.get_attrs.split(';')
            version = attrs.split(',')
            self.version = version[0]
            need_to_save = True 
        return need_to_save 

    def save(self, *args, **kwargs):
        super(NodeType, self).save(*args, **kwargs)
        if self.initstate():
            super(NodeType, self).save(*args, **kwargs)


class Key(models.Model):
    name = models.CharField(max_length=150, default='setme')
    decrypt_key = models.CharField(default='setme', max_length=200, verbose_name='Decryption key', help_text=mark_safe(settings.HELP_DECRYPT_KEY))

    def __str__(self):
        return self.name

    def get_key(self):
        return self.decrypt_key

    def initstate(self):
        need_to_save = False
        if len(self.name) < int(6):
            self.name = secrets.token_urlsafe(10)
            self.decrypt_key = Fernet.generate_key().decode()
            need_to_save = True
        return need_to_save

    def save(self, *args, **kwargs):
        super(Key, self).save(*args, **kwargs)
        if self.initstate():
           super(Key, self).save(*args, **kwargs)


