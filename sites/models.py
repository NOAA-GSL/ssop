from django.db import models
from django.apps import apps
from django.contrib.auth.models import User, Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.mail import send_mail, EmailMessage
from django.utils.timezone import now
from django.utils.safestring import mark_safe
from hashlib import md5
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidSignature
import base64
from django_auth_saml.backend import user_has_authenticated, user_login_failure
from django.core.exceptions import SuspiciousFileOperation
from django_contrib_auth.backends import local_user_has_authenticated, local_user_cannot_authenticate, local_user_password_rejected
from django.dispatch import receiver, Signal
from smtplib import SMTPException

import ast
import datetime
import hashlib
import pytz
import random
import secrets
import logging
import os
import pprint
import subprocess
import sys
import time

logger = logging.getLogger('ssop.models')

from ssop import settings

user_logged_out = Signal()

def runcmdl(cmdl, execute):
    """
    prints cmdl or passes it to subprocess.run if execute is True
    returns status, result as strings
    """

    cmd = " ".join(cmdl)
    status = int(-1)
    result = "execute = " + str(execute) 
    if 'true' in str(execute).lower():
        try:
            instance = subprocess.run(cmdl, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            status = instance.returncode
            if status != int(0):
                result = instance.stderr.decode()
                raise OSError
            result = instance.stdout.decode()
        except OSError as e:
            result = "exception: " + str(e) + ", result = " + str(result)
    return status, result

def get_sso_uid(ssostr):
    qs = SSOObj.objects.filter(ssostr=ssostr)
    if qs.count() == int(1):
        ssouid = qs[0].get_email()
    else:
        ssouid = None
    return str(ssouid)

def get_and_remove_sso_email(ssostr):
    qs = SSOObj.objects.filter(ssostr=ssostr)
    if qs.count() == int(1):
        ssouid = qs[0].get_email()
        qs[0].delete()
    else:
        ssouid = None
    return ssouid

def add_sso_obj(ssostr, email, icamattrs):
    for ssoe in SSOObj.objects.filter(email=email):
        ssoe.delete()
    newsso = SSOObj(ssostr=ssostr, email=email, icamattrs=icamattrs)
    newsso.save()
    return newsso.get_email() 

def get_or_add_authtoken(token):
    qs = AuthToken.objects.filter(token=token)
    if qs.count() == int(0):
        if 'newtoken' in str(token):
            rettoken = AuthToken()
        else:
            rettoken = AuthToken(token=token)
        rettoken.save()
    else:
        rettoken = qs[0]
    return rettoken

def get_or_add_sysadmin(user, homeorg, orglist):
    try:
        uqs = User.objects.filter(email=user.email)
        if uqs.count() == 0:
            user = uqs[0]

        horg = get_or_add_organization_by_name(homeorg)
        qs = Sysadmin.objects.filter(username__email=user.email)
        if qs.count() == 0:
            sa = Sysadmin(username=user, organization=horg)
            sa.save()
        else:
            sa = qs[0]

        for orgname in orglist:
            thisorg = get_or_add_organization_by_name(orgname)
            sa.organizations.add(thisorg)

        #sa.organization = horg
        sa.organizations.add(horg)
        sa.save()
    except UserWarning as e:
        now = datetime.datetime.utcnow()
        msg = str(now) + ":UserWarning:" + str(user.email) + ":e = " + str(e)
        logger.info(msg)

def add_sysadmins():

    # Start from an initialized database or run command 'clean_system' and then manually run the sql commands
    # to insure auto increment for organization table has been reset
    # mysql -u 'username' -p ...
    # use 'the_proper_database_name'
    # alter table provision_organization auto_increment=1;

    # Need none Organization
    orgname = settings.NONE_NAME
    thisorg = get_or_add_organization_by_name(orgname)
    now = datetime.datetime.utcnow()
    allusers = User.objects.all()
    for username in settings.SSOP_SYSADS.keys():
        homeorg = settings.SSOP_SYSADS[username]['homeorg']
        orglist = settings.SSOP_SYSADS[username]['divisions']
        orglist.append(settings.NONE_NAME)
        usertype = settings.SSOP_SYSADS[username]['type']
        splitname = str(username).split('.')
        firstname = splitname[0].capitalize()
        lastname = splitname[len(splitname) - 1].capitalize()

        if str(usertype) == 'icam':
            email = username + '@noaa.gov'
        else:
            email = settings.SSOP_SYSADS[username]['email']
        email = str(email).lower()

        user = ''
        need_to_create = True
        for u in allusers:
            uemail = str(u.email).lower()
            if email in uemail:
                user = u
                need_to_create = False

                now = datetime.datetime.utcnow()
                break

        now = datetime.datetime.utcnow()
        if need_to_create:
            user = User.objects.create_user(username=username, email=email, is_staff=True,
                                            first_name=firstname, last_name=lastname)
            user.save()

        if str(usertype) != 'local' and str(usertype) != 'superuser' and str(usertype) != 'localdev':
            minlen = settings.LOCAL_PASSWORD_MINIMUM_LENGTH
            maxlen = 2 * minlen
            user.set_password(secrets.token_urlsafe(random.randint(minlen, maxlen)))
            user.save()
        elif str(usertype) == 'localdev':
            if need_to_create:
                password = secrets.token_urlsafe(random.randint(6, 8))
                user.set_password(password)
                user.save()

                subject = "creds"
                body = str(password)
                fromaddr = settings.EMAIL_HOST_USER
                toaddr = [email]
                try:
                    send_mail(subject, body, fromaddr, toaddr, fail_silently=False)
                except SMTPException as e:
                    msg = str(now) + ":Send password failed:" + str(username)
                    logger.info(msg)

            groupnames = ['cn=_OAR ESRL GSL Sysadm,cn=groups,cn=nems,ou=apps,dc=noaa,dc=gov',
                          'cn=_OAR ESRL GSL All Personnel,cn=groups,cn=nems,ou=apps,dc=noaa,dc=gov']
            now = datetime.datetime.utcnow()
            try:
                for group in groupnames:
                    newgroup = Group.objects.get(name=group)
                    user.groups.add(newgroup)
                user.save()
            except Group.DoesNotExist as e:
                msg = str(now) + ":" + str(e) + ':' + str(username)
                logger.info(msg)
        get_or_add_sysadmin(user, homeorg, orglist)

        # pause a moment to allow objects to created (Organizations were being duplicated)
        naptime = 1
        time.sleep(naptime)

def add_groups_and_permissions():

    perms = ['add', 'change', 'delete', 'view']
    for groupname in settings.AUTH_SAML_GROUPS.keys():
        groupname = str(groupname)

        now = datetime.datetime.utcnow()
        try:
            group = Group.objects.get(name=groupname)
            group.permissions.clear()
        except Group.DoesNotExist as e:
            group = Group.objects.create(name=groupname)
            group.save()

        for mname in settings.AUTH_SAML_GROUPS[groupname]['modelslist']:
            try:
                model = apps.get_model('sites', mname)
            except LookupError:
                model = None

            if model is None:
                try:
                    model = apps.get_model('auth', mname)
                except LookupError:
                    model = "not_found_in_sites_or_auth"

            ct = ContentType.objects.get_for_model(model)
            for p in perms:
                cn = p + '_' + model._meta.model_name
                permission = Permission.objects.get(codename=cn, content_type=ct)
                group.permissions.add(permission)

        for mname in settings.AUTH_SAML_GROUPS[groupname]['viewmodels']:
            model = apps.get_model('sites', mname)
            ct = ContentType.objects.get_for_model(model)
            cn = 'view_' + model._meta.model_name
            permission = Permission.objects.get(codename=cn, content_type=ct)
            group.permissions.add(permission)

        group.save()
        now = datetime.datetime.utcnow()
        msg = str(now) + ":GroupobjectAddedPerms:" + groupname
        logger.info(msg)

def add_datacenter_rooms():
    for room in settings.DATA_CENTER_ROOMS.keys():
        qs = Room.objects.all().filter(name=str(room))
        if qs.count() < int(1):
            name = settings.DATA_CENTER_ROOMS[room]['name']
            state = settings.DATA_CENTER_ROOMS[room]['state']
            newroom = Room(number=str(room), name=name, current_state=state)
            newroom.save()

def add_none_token():
    token = get_or_add_authtoken(settings.NONE_NAME)
    token.set_expire_time(settings.NONE_NEVER_EXPIRES)
    token.set_renewed(settings.NONE_NEVER_EXPIRES)

def add_none_contact():
    contacts = Contact.objects.filter(email=settings.NONE_EMAIL, firstname='none', lastname='none')
    if contacts.count() == int(0):
        newcontact = Contact.objects.create(email=settings.NONE_EMAIL, firstname='none', lastname='none')
        newcontact.save()
    contacts = Contact.objects.filter(email=settings.ANYONE_EMAIL, firstname='anyone', lastname='anywhere')
    if contacts.count() == int(0):
        newcontact = Contact.objects.create(email=settings.ANYONE_EMAIL, firstname='anyone', lastname='anywhere')
        newcontact.save()

def add_none_project():
    project = Project.objects.filter(name=settings.NONE_NAME)
    if project.count() == int(0):
        newproject = Project.objects.create(name=settings.NONE_NAME)
        newproject.save()
   
def add_contacts_list(userlist):
    for line in userlist.split('\n'):
        line = str(line)
        msg = "line: " + line
        if "," in line:
            logger.info(msg)
            email, firstname, lastname = line.split(',')
            qs = Contact.objects.filter(email=email)
            if qs.count() == int(0):
                newcontact = Contact.objects.create(email=email, firstname=firstname, lastname=lastname)
                newcontact.save()
  
def check_for_update(filename):
    #msg = "    check_for_update " + str(filename)
    #logger.info(msg)
    stats = os.stat(filename)
    temp = str(filename).replace("/","_",10)
    temp = temp.split('_')
    fn = 'unknown'
    if len(temp) > int(1):
        fn = temp[len(temp)-1]
    prevfn = "/usr/share/nginx/html/uploads/stats_" + fn + ".prev"
    need_to_update = False 

    prevctime = 0.0
    if os.path.exists(prevfn):
        fp = open(prevfn, 'r')
        prevctime = fp.read()
        fp.close()
        
    if float(stats.st_ctime) > float(prevctime):
        need_to_update = True
        fp = open(prevfn, 'w')
        fp.write(str(stats.st_ctime))
        fp.close()

    return need_to_update 
       
 
def review_contacts():
    utcstart = datetime.datetime.utcnow()
    utcstart = utcstart.replace(tzinfo=pytz.UTC)
    utcstart = utcstart.replace(microsecond = 0)
    msg = "\n\n   review_contacts -- utcstart: " + str(utcstart)
    logger.info(msg)
    msg = "   CONTACT_RENEWAL_PERIOD_TIMEDELTA: " + str(settings.CONTACT_RENEWAL_PERIOD_TIMEDELTA)
    logger.info(msg)
    msg = "   ACCOUNT_REVIEW_NAPTIME: " + str(settings.ACCOUNT_REVIEW_NAPTIME)
    logger.info(msg)
    loopcount = int(1)
    while True:
        checkname = "/opt/ssop/ssop/settings.py"
        if check_for_update(checkname):
            msg = "   need to update -- exiting"
            logger.info(msg)
            sys.exit(-1)
        #else:
        #    msg = "   " + str(checkname) + " is up to date"
        #    logger.info(msg)

        utcnow = datetime.datetime.utcnow()
        utcnow = utcnow.replace(tzinfo=pytz.UTC)
        utcnow = utcnow.replace(microsecond = 0)
        msg = str(loopcount) + " -- " + str(utcnow)
        #logger.info(msg)
        for token in AuthToken.objects.all():
            if utcnow > token.get_expiration_time():
                if settings.NONE_NAME not in str(token):
                    msg = "       deleting token: " + str(token)
                    for user in Contact.objects.all():
                        if str(token) in str(user.get_renewal_tokens()):
                            msg = msg + " for " + str(user)
                            break 
                    #msg = "       NOT deleting token: " + str(token)
                    token.delete()
                    logger.info(msg)
            
        none_email = str(settings.NONE_EMAIL)
        none_email = none_email.replace('#', '')
        for user in Contact.objects.all():
            if none_email in str(user.email):
                continue
  
            # For development/debugging purposes -- we don't want to bombard folks with possible erroneous output.
            if len(settings.EMAIL_TEST_USERS) > int(0): 
                if str(user.email) not in str(settings.EMAIL_TEST_USERS):
                    continue
            
        none_email = str(settings.NONE_EMAIL)
        none_email = none_email.replace('#', '')
        for user in Contact.objects.all():
            if none_email in str(user.email):
                continue
    
            if len(settings.EMAIL_TEST_USERS) > int(0): 
                if str(user.email) not in str(settings.EMAIL_TEST_USERS):
                    continue

            utcnow = datetime.datetime.utcnow()
            utcnow = utcnow.replace(tzinfo=pytz.UTC)
            utcnow = utcnow.replace(microsecond = 0)
            msg = "    utcnow: " + str(utcnow)
            #logger.info(msg)
    
            last_connected = user.last_connected() 
            msg = "       user: " + str(user) + "   last_connected: " + str(last_connected) 
    
            renewal_tokens = user.get_renewal_tokens()
            num_tokens = renewal_tokens.count()

            msg = msg + " and has " + str(num_tokens) + " renewal tokens"
            #logger.info(msg)

            if user.get_renewal_tokens().count() == int(2):
                if none_email in str(user.email):
                    continue
                try:
                    user.delete()
                    msg = " ----- account " + str(user) + " deleted ----- "
                except ValueError:
                    msg = " ----- failed to delete account " + str(user) + " ValueError ----- "
                logger.info(msg)
             

            if num_tokens <= int(1):
                renewal_token = get_or_add_authtoken('newtoken')
                renewal_token.save()
                expires_dt = utcnow + settings.CONTACT_RENEWAL_PERIOD_TIMEDELTA
                renewal_token.set_expire_time(expires_dt + datetime.timedelta(seconds=settings.EXPIRES_DT_DELTASECONDS))
                if str(settings.DEFAULT_DATETIME) in str(last_connected):
                    renewal_token.set_renewed(utcnow + datetime.timedelta(seconds=settings.EXPIRES_DT_DELTASECONDS))
                else:
                    renewal_token.set_renewed(expires_dt + datetime.timedelta(seconds=settings.EXPIRES_DT_DELTASECONDS))
                    msg = "       " + str(user) + " renewed via token" 
                    logger.info(msg)
                user.add_renewal_token(renewal_token)
                for dt in settings.CONTACT_RENEWAL_PERIOD_WARNINGS:
                    accessed = expires_dt - dt
                    renewal_token = get_or_add_authtoken('newtoken')
                    renewal_token.save()
                    renewal_token.set_expire_time(expires_dt)
                    renewal_token.set_renewed(accessed)
                    user.add_renewal_token(renewal_token)
                msg = "       " + str(user) + " queued for removal" 
                logger.info(msg)

            for rt in user.get_renewal_tokens():
                expires = rt.get_expiration_time()
                if utcnow > expires:
                    try:
                        if settings.NONE_NAME not in str(rt):
                            rt.delete()
                            msg = " ----- DELETED token ----- " + str(rt) + " for " + str(user) + " at " + str(utcnow)
                    except ValueError as ve:
                        msg = " ----- value error ve: " + str(ve)
                    logger.info(msg)

            for rt in user.get_renewal_tokens():
                #msg = "        rt: " + str(rt)
                #logger.info(msg)
                if settings.NONE_NAME in str(rt.token):
                    continue

                #msg = "        rt: " + str(rt)
                #logger.info(msg)
                expires = rt.get_expiration_time()
                #msg = "    renewal_token " + str(rt) + " expires at " + str(expires)
                #logger.info(msg)
                warned = rt.get_renewal_time()
                #msg = "    renewal_token warned: " + str(warned)
                #logger.info(msg)

                body_comment = ''
                #print("   utcnow + settings.CRPT: " + str(utcnow + settings.CONTACT_RENEWAL_PERIOD_TIMEDELTA))
                #logger.info(msg)

                if utcnow >= warned:
                    #msg = "  utcnow >= warned:"
                    #logger.info(msg)
                    #msg = "            warned: " + str(warned)
                    #logger.info(msg)
                    #msg = "            utcnow: " + str(utcnow)
                    #logger.info(msg)
                    expires = expires.replace(microsecond = 0)
                    expiresstr = expires.strftime('%Y-%m-%d %H:%M:%S')
                    warned = warned.replace(microsecond = 0)
                    warnedstr = warned.strftime('%Y-%m-%d %H:%M:%S')
                    lcdt = last_connected.replace(microsecond = 0)
                    lcdt = lcdt.strftime('%Y-%m-%d %H:%M:%S')

                    removed_in_dtdelta = expires - warned
                    removed_in_dtdeltastr = str(removed_in_dtdelta)
                    if ',' in str(removed_in_dtdeltastr):
                        removed_in_dtdeltastr = removed_in_dtdeltastr.replace(', 0:00:00', '')

                    kwargs = {"user": user, "lcdt": lcdt, "body_comment": body_comment}
                    kwargs["renewal_token"] = rt
                    kwargs["expires_datetime"] = expiresstr
                    kwargs["warned_datetime"] = warnedstr
                    kwargs["removed_in_dtdelta"] = removed_in_dtdeltastr
                    send_removal_notice_email(kwargs)
                    msg = "            ----- SEND_removal_notice_email ----- rt = " + str(rt) 
                    logger.info(msg)
                    rt.set_renewed(settings.NONE_NEVER_EXPIRES)
                #else:
                #    msg = "   utcnow < warned"
                #    logger.info(msg)

            #msg = "           ------ user.get_renewal_tokens().count(): " + str(user.get_renewal_tokens().count())
            #logger.info(msg)

        if int(settings.ACCOUNT_REVIEW_NAPTIME) > int(0):
            #msg = "    sleeping " + str(settings.ACCOUNT_REVIEW_NAPTIME) + ' seconds.'
            #logger.info(msg)
            time.sleep(settings.ACCOUNT_REVIEW_NAPTIME)
            #msg = "    done sleeping"
            #logger.info(msg)
        else:
            msg = "    exiting .... " + str(settings.ACCOUNT_REVIEW_NAPTIME) + ' seconds.'
            logger.info(msg)
            sys.exit(-1)
        utcnow = datetime.datetime.utcnow()
        utcnow = utcnow.replace(tzinfo=pytz.UTC)
        utcnow = utcnow.replace(microsecond = 0)
        #msg = "    end of loop " + str(loopcount) + " at " + str(utcnow)
        #logger.info(msg)
        loopcount = int(1) + loopcount


def hash_to_fingerprint(data):
    dkeys = []
    for k in data.keys():
        dkeys.append(k)
    if len(dkeys) > int(0):
        dkeys.sort()

    dstring = ''
    for k in dkeys:
        dstring = data[k] + ':' + dstring
    dstring = dstring.encode()
    fp = md5(dstring).hexdigest()
    return fp

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

def get_or_add_contact(email, firstname=None, lastname=None):
    qs = Contact.objects.filter(email=email)
    if qs.count() < int(1):
        if firstname and lastname:
            ac = Contact(email=email, firstname=firstname, lastname=lastname)
        else:
            ac = Contact(email=email)
        ac.save()
    else:
        ac = qs[0]
    return ac 

def get_or_add_group(name):
    qs = Group.objects.filter(name=name)
    if qs.count() < int(1):
        ag = Group(name=name)
        ag.save()
    else:
        ag = qs[0]
    return ag

def get_or_add_organization_by_name(name):
    qs = Organization.objects.filter(name=name)
    if qs.count() < int(1):
        org = Organization(name=name)
        org.save()
    else:
        org = qs[0]
    return org

def add_organization_relationship(parent, child):
    cqs = Organization.objects.filter(name=child.name)
    if cqs.count() == int(1):
        child = cqs[0]
        pqs = Organization.objects.filter(name=parent.name)
        if pqs.count() == int(0):
            child.parent = pqs[0]
            child.save()
          
def get_or_add_decrypt_key(keyname=None, dk=None):
    key = None
    if keyname is not None:
        qs = Key.objects.filter(name=keyname)
        if qs.count() == int(1):
            key = qs[0]
    if key is None:
        if dk:
           key = Key(name=keyname, decrypt_key=dk)
        else:
           key = Key()
        key.save()
    return key

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
        keyname = project["decrypt_key"]
        org = get_or_add_organization_by_name(og)
        key = get_or_add_decrypt_key(keyname=keyname, dk=None)
        np = Project(name=name, display_order=do, queryparam=qp, enabled=en, verbose_name=vn, organization=org, return_to=rt, error_redirect=er, decrypt_key=key)
        np.save()
    else:
        np = qs[0]
    return np

def get_upload_path(self, filename):
    return str(filename)

def clean_authtokens():
    for token in AuthToken.objects.all():
        value = token.get_token()


class About(models.Model):
    """
    Info about SSOP Sandbox 
    """
    Version = models.CharField(max_length=50, null=True, default='version', verbose_name='Version')
    Requirements = models.TextField(max_length=2000, null=True, default='requirements', verbose_name='Requirements')
    updated = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'About'
        verbose_name_plural = 'About'

    def __str__(self):
        return self.Version

    def get_fields(self):
        return [(field.name, getattr(self,field.name)) for field in About._meta.fields]

    def version(self):
        return str(self.Version)

    def requirements(self):
        return self.Requirements

    def updated_mst(self):
        when = str(self.updated).split('.')
        when = when[0]
        when = datetime.datetime.strptime(when, '%Y-%m-%d %H:%M:%S')
        return str(when)

    def initstate(self):
        needtoupdate = True 
        msg = "     about initstat: " + str(self.version())
        logger.info(msg)
        if self.version() not in settings.SSOPSB_VERSION:
            needtoupdate = True
            self.Version = settings.SSOPSB_VERSION

            cmdl = ['pip', 'list']
            status, result = runcmdl(cmdl, True)
            req = ''
            if status == int(0):
                for item in result.split('\n'):
                    if 'Package' not in item and '---' not in item and len(item) > int(1):
                        req = req + str(item) + ',\n'
                if len(req) > int(2):
                    self.Requirements = req[:-2]
            else:
                msg = 'status not 0 running ' + str(cmdl)
                logger.info(msg)
        else:
            needtoupdate = False 

        msg = "     needtoupdate: " + str(needtoupdate)
        logger.info(msg)
        return needtoupdate

    def save(self, *args, **kwargs):
        super(About, self).save(*args, **kwargs)
        if self.initstate():
            super(About, self).save(*args, **kwargs)


class Contact(models.Model):
    firstname = models.CharField(max_length=150, default='firstname')
    lastname = models.CharField(max_length=150, default='lastname')
    email = models.EmailField(unique=True, null=True, blank=settings.NONE_EMAIL, help_text=mark_safe(settings.HELP_CONTACT_EMAIL))
    last_connection_time = models.DateTimeField(null=True, default=settings.DEFAULT_DATETIME)
    renewal_tokens = models.ManyToManyField('AuthToken', related_name='contact_renewal_tokens')
    organizations = models.ManyToManyField('Organization', related_name='contact_organizations')
    organization = models.ForeignKey('Organization', default=1, related_name='contact_organization',
                                     verbose_name='Primary Organization', on_delete=models.CASCADE)

    def __str__(self):
        return  self.firstname + ' ' + self.lastname + ' (' + str(self.email) + ')'

    def get_fields(self):
        return [(field.name, getattr(self,field.name)) for field in Contact._meta.fields]

    def save(self, *args, **kwargs):
        super(Contact, self).save(*args, **kwargs)
        if self.initstate():
            super(Contact, self).save(*args, **kwargs)

    def initstate(self):
        need_to_update = False
        if settings.NONE_EMAIL not in self.email:
            email = str(self.email).lower()
            msg = "   initstate email: " + str(email)
            logger.info(msg)
            namestr, domains = str(self.email).split('@')
            if 'firstname' in self.firstname:
                namestr = str(namestr).split('.')
                self.firstname = namestr[0].capitalize()
                self.lastname = namestr[len(namestr) - 1].capitalize()
                self.last_connection_time = settings.DEFAULT_DATETIME
                need_to_update = True

            try:
                if settings.NONE_NAME in str(self.organization): 
                    domains = str(domains).split('.')
                    #msg = "   domains: " + str(domains)
                    #logger.info(msg)
                    homeorg = get_or_add_organization_by_name(domains[0])
                    #msg = "   homeorg: " + str(homeorg)
                    #logger.info(msg)
                    homeorg = get_or_add_organization_by_name(domains[0])
                    childorg = homeorg
                    self.organization = homeorg
                    self.organizations.add(homeorg)
                    self.last_connection_time = settings.DEFAULT_DATETIME
                    for d in domains:
                        neworg = get_or_add_organization_by_name(d)
                        #msg = "   neworg: " + str(neworg)
                        #logger.info(msg)
                        self.organizations.add(neworg)
                        if neworg == childorg:
                            continue
                        add_organization_relationship(neworg, childorg)
                        #msg = "add_organization_relationship( " + str(neworg) + ", " + str(childorg) + " )"
                        #logger.info(msg)
                        childorg = neworg
                    need_to_update = True
            except ValueError:
                pass
        return need_to_update
              
    def get_value(self):
        rv = {}
        rv['firstname'] = self.firstname
        rv['lastname'] = self.lastname
        rv['email'] = self.email
        return str(rv)

    def last_connected(self):
        return self.last_connection_time

    def set_connected(self):
        utcnow = datetime.datetime.utcnow()
        utcnow = utcnow.replace(tzinfo=pytz.UTC)
        self.last_connection_time = utcnow
        self.save()

    def last_renewed(self):
        return self.renewal_time

    def get_renewal_tokens(self):
        try:
            qs = self.renewal_tokens.get_queryset()
        except:
            qs = AuthToken.objects.filter(token=settings.NONE_NAME)
        return qs

    def add_renewal_token(self, token):
        self.renewal_tokens.add(token)
        self.save()

    def set_renewed(self):
        utcnow = datetime.datetime.utcnow()
        utcnow = utcnow.replace(tzinfo=pytz.UTC)
        self.last_connection_time = utcnow
        #msg = "      set_renewed --- Contact " + str(self) + " lct = " + str(self.last_connection_time)
        #logger.info(msg)
        for t in self.get_renewal_tokens():
            if settings.NONE_NAME not in str(t):
                t.delete() 
                msg = "       in set_renewed -- deleted token t: " + str(t)
                logger.info(msg)
        self.save()
        #msg = "      set_renewed --- Contact self " + str(self) + " last connected = " + str(self.last_connected())
        #logger.info(msg)

    def organizations_list(self):
        olist = []
        for o in self.organizations.get_queryset():
            olist.append(str(o))
        if len(olist) > int(1):
           olist.sort
        return olist

    def projects(self):
        projects = []
        for p in Project.objects.all():
            if p.authorized(self):
                projects.append(str(p))
        if len(projects) > int(1):
            projects.sort()
        return projects 


class Project(models.Model):
    name = models.CharField(max_length=150, default='newproject', help_text=mark_safe(settings.HELP_NAME))
    organization = models.ForeignKey('sites.Organization', null=True, blank=True, on_delete=models.CASCADE, help_text=mark_safe(settings.HELP_ORGANIZATION))
    verbose_name = models.CharField(max_length=150, default='newproject verbose', help_text=mark_safe(settings.HELP_VERBOSE_NAME))
    return_to = models.CharField(max_length=150, default=settings.LOGINDOTGOV_RETURN_TO, help_text=mark_safe(settings.HELP_RETURN_TO))
    queryparam = models.BooleanField(default=True, verbose_name='Token on url', help_text=mark_safe(settings.HELP_QUERYPARAM))
    querydelimiter = models.CharField(default='?access_token=', max_length=24, verbose_name='URL query delimiter')
    error_redirect = models.CharField(max_length=150, default=settings.LOGINDOTGOV_ERROR_REDIRECT, help_text=mark_safe(settings.HELP_ERROR_REDIRECT))
    state = models.CharField(max_length=50, null=True, default='setme', help_text=mark_safe(settings.HELP_STATE))
    decrypt_key = models.ForeignKey('sites.Key', null=True, blank=True, on_delete=models.SET_NULL, help_text=mark_safe(settings.HELP_DECRYPT_KEY_NAME))
    updated = models.DateTimeField(auto_now_add=True)
    enabled = models.BooleanField(default=False, help_text=mark_safe(settings.HELP_ENABLED))
    expiretokens = models.BooleanField(default=False, help_text=mark_safe(settings.HELP_EXPIRETOKENS))
    display_order = models.IntegerField(default=0, help_text=mark_safe(settings.HELP_DISPLAY_ORDER))
    graphnode = models.ForeignKey('sites.GraphNode', null=True, blank=True, on_delete=models.SET_NULL, help_text=mark_safe(settings.HELP_GRAPHNODE))
    logoimg = models.ImageField(upload_to = get_upload_path, verbose_name="Logo Image", null=True, blank=True, help_text=mark_safe(settings.HELP_LOGOIMG))
    logobin = models.BinaryField(null=True, blank=True)
    owner = models.ForeignKey('sites.Contact', null=True, blank=True, on_delete=models.SET_NULL, help_text=mark_safe(settings.HELP_PROJECT_OWNER))
    userlist = models.ManyToManyField('sites.Contact', related_name='project_userlist', help_text=mark_safe(settings.HELP_USERLIST))
    app_params = models.TextField(max_length=4096, null=True, default='{}', help_text=mark_safe(settings.HELP_APP_PARAMS))
    pfishing_resistant = models.BooleanField(default=False, help_text=mark_safe(settings.HELP_PFISHING_RESISTANT))
    IDP_TYPE_SELECT = (('0', 'Login.gov'), ('1', 'ICAM'), ('2', 'Both ICAM and Login.gov -- two access urls will be available'))
    idp = models.CharField(verbose_name='Identity Provider', max_length=80, choices=IDP_TYPE_SELECT, default='0', help_text=mark_safe(settings.HELP_IDP))
    groups = models.ManyToManyField(Group, verbose_name='ICAM groups', related_name='project_groups', help_text=mark_safe(settings.HELP_ICAM_GROUPS))
    
    #field_order = ('name', 'organization', 'verbose_name', 'return_to', 'error_redirect', 'enabled', 'display_order', 'decrypt_key', 'logoimg', 'userlist', 'expiretokens', 'graphnode', 'state', 'queryparam', 'querydelimiter', )
    #field_order = ('name', 'organization', 'verbose_name', 'return_to', 'error_redirect', 'enabled', 'display_order', 'decrypt_key', 'logoimg', 'expiretokens', 'graphnode', 'state', 'queryparam', 'querydelimiter', )

    def __str__(self):
        return self.name

    #def get_fields(self):
    #    return [(field.name, getattr(self,field.name)) for field in Project._meta.fields]
    def get_fields(self):
        retlist =  []
        for field in Project._meta.fields:
            k = field.name
            v = getattr(self,field.name)
            if v is None:
                v = "None"
            retlist.append((k,v))

        retlist.append(('userslist', self.get_all_users()))
        retlist.append(('groupslist', self.groupslist()))
        return retlist

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

        if self.logoimg is not None:
            pdir = settings.STATIC_ROOT + 'projects/' + str(self.name)
            if not os.path.exists(pdir):
                os.makedirs(pdir)
            destination_filename = pdir + '/logo'

            filetype = None
            imgpath = None
            try:
                imgpath = self.logoimg.path
                for ft in settings.LOGO_FILETYPES:
                    if str(imgpath).endswith(ft):
                        filetype = ft
                        break
                #msg = "   filetype is: " + str(filetype)
                #logger.info(msg)
                if filetype:
                    if os.path.exists(imgpath):
                        os.rename(imgpath, destination_filename)
                        fp = open(destination_filename, 'rb')
                        self.logobin = fp.read()
                        fp.close()
                        need_to_save = True
            except ValueError as ve:
                imgpath = '   ve: ' + str(ve)
            except SuspiciousFileOperation as sfo:
                imgpath = '   sfo: ' + str(sfo)
            #msg = "   imgpath is: " + str(imgpath)
            #logger.info(msg)

        if not settings.DEBUG:
            if not self.expiretokens:
                self.expiretokens = True
                need_to_save = True 

        # Add the file from the DB if it does not exist
        #msg = "      self.get_logo() is currently: " + str(self.get_logo())
        #logger.info(msg)
        #if logostr is not None:
        #    msg = "      logostr is: " + logostr 
        #    logger.info(msg)
        #    if self.get_logobin() is not None:
        #       filepath = pdir + '/' + filename
        #       msg = "          filepath is: " + filepath
        #       logger.info(msg)
        #       if not os.path.exists(filepath):
        #           fp = open(filepath, 'wb')
        #           fp.write(self.get_logobin())
        #           fp.close()
        #           self.logo = filepath
        #           need_to_save = True 
        #    else:
        #       msg = "          self.get_logobin() is " + str(self.get_logobin())
        #       logger.info(msg)

        return need_to_save

    def save(self, *args, **kwargs):
        utcnow = datetime.datetime.utcnow()
        self.updated = utcnow.replace(tzinfo=pytz.UTC)
        super(Project, self).save(*args, **kwargs)
        if self.initstate():
            super(Project, self).save(*args, **kwargs)

    def get_returnto(self):
        return self.return_to

    def get_err_redirect(self):
        return self.error_redirect

    def get_state(self):
        return self.state

    def not_pfishable(self):
        return self.pfishing_resistant

    def get_idp_type(self):
        idptype = []
        if '0' in str(self.idp):
            idptype.append(('ldg/', 'login.gov'))
        if '1' in str(self.idp):
            idptype.append(('icam/', 'ICAM'))
        if '2' in str(self.idp):
            idptype.append(('ldg/', 'login.gov'))
            idptype.append(('icam/', 'ICAM'))
        return idptype 

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

    def get_did(self):
        did = None 
        try:
            ale = ast.literal_eval(self.get_app_params())
            did = ale['fernet-key-id'] 
        except KeyError:
            pass
        return did 

    def is_enabled(self):
        return self.enabled

    def append_access_token(self):
        return self.queryparam

    def get_logo(self):
        return self.logo

    def showlogobin(self):
        blen = int(0)
        if self.get_logobin() is not None:
            blen = len(self.get_logobin())
        return str(blen) + ' chars'

    def get_groups(self):
        groups = []
        for g in self.groups.get_queryset():
            groups.append(g.name)
        return groups

    def get_logobin(self):
        return self.logobin

    def get_app_params(self):
        return self.app_params

    def list_app_params(self):
        params = at = ast.literal_eval(self.get_app_params())
        retstr = str(len(params.keys())) + ' parameters'
        return retstr 

    def users(self):
        users = []
        for a in self.userlist.get_queryset():
            users.append(str(a))
        if len(users) > int(1):
            users.sort()

        # MAXUSERLIST makes the GUI less cluttered 
        if len(users) <= int(settings.MAXUSERLIST):
            retstr = ''
            for u in users:
               retstr = retstr + str(u) + ','
            # clean trailing , to make GUI look nice
            retstr = retstr[:-1]
        else:
            retstr = str(len(users)) + " users"
        return retstr

    def get_all_users(self):
        users = []
        for a in self.userlist.get_queryset():
            users.append(str(a))
        if len(users) > int(1):
            users.sort()
        retstr = ''
        for u in users:
           retstr = retstr + str(u) + ','
        # leave trailing , to facilitate splitting
        return retstr

    def groupslist(self):
        grouplist = []
        for g in self.groups.get_queryset():
            grouplist.append(str(g))
        if len(grouplist) > int(1):
            grouplist.sort()
        retstr = ''
        # ICAM groups contain multiple commas as a delimiter, so a : facilitates downstream splitting
        for g in grouplist:
           retstr = retstr + str(g) + ':'
        return retstr 

    def num_groups(self):
        grouplist = self.groupslist()
        retstr = str(len(grouplist)) + " groups"
        return retstr

    def authorized(self, uu):
        #msg = "    authorized uu: " + str(uu)
        #logger.info(msg)

        auth = False 
        if settings.DEFAULT_PROJECT_NAME in self.name:
            auth = True
        if self.name.startswith('demo'):
            auth = True

        try:
            email = uu['email']
        except KeyError:
            email = 'noemail'
        email = str(email).lower()
        for a in self.userlist.get_queryset():
            if email in str(a).lower():
                auth = True
                break
        if auth:
            msg = str(email) + " is authorized"
        else:
            msg = str(email) + " NOT AUTHORIZED"
        #msg = msg + " for " + self.name
        #logger.info(msg)
        return auth

    def icam_authorized(self, uu):
        auth = False

        pgroups = set()
        for g in self.get_groups():
            pgroups.add(g)
        #msg = "    icam_authorized -- project_groups: " + str(pgroups)
        #logger.info(msg)

        sqs = SSOObj.objects.filter(email=uu)
        if sqs.count() > int(0):
            icamattrs = sqs[0].get_icamattrs()
            ale = ast.literal_eval(icamattrs)
            try:
                sso_groups = set()
                for g in ale['isMemberOf']:
                    sso_groups.add(g)
                #msg = "    icam_authorized -- sso_groups: " + str(sso_groups)
                #logger.info(msg)
            except KeyError:
                #msg = "    icam_authorized -- NO sso_groups"
                #logger.info(msg)
                pass
            
            auth = pgroups.issubset(sso_groups)
            #msg = "    icam_authorized -- auth: " + str(auth)
            #logger.info(msg)
        return auth

    def contact_emails(self):
        users = []
        for a in self.userlist.get_queryset():
            users.append(str(a.email))
        return str(users)

    def contacts_url(self):
        return settings.CONTACTS_URL + str(self.state)[0:4]


class Attributes(models.Model):
    fingerprint = models.CharField(max_length=150, default='setme')
    decodedfingerprint = models.CharField(max_length=150, default='setme')
    attrs = models.TextField(default='')
    decodedattrs = models.TextField(default='showme')
    #graphnode = models.ForeignKey('sites.GraphNode', null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        verbose_name_plural = 'Attributes'

    def __str__(self):
        return self.fingerprint

    def get_fields(self):
        retlist =  []
        for field in Attributes._meta.fields:
            k = field.name
            v = getattr(self,field.name)
            if v is None:
                v = "None"
            if str(k) == 'updated':
                v = str(v)
            retlist.append((k,v))
        return retlist

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
            need_to_save = True 

        if 'showme' in str(self.decodedattrs):
            #if settings.DEBUG:
            if True:
                fernet = Fernet(settings.DATA_AT_REST_KEY_ATTRS)
                attrs = bytes_in_string(self.get_attributes())
                self.decodedattrs = fernet.decrypt(attrs).decode()
            else:
                self.decodedattrs = "Decoded attributes not available."
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

    def redact_attr(self):
        fernet = Fernet(settings.DATA_AT_REST_KEY_ATTRS)
        try:
            # must be valid syntax for ast.literaleval (json)
            msg = str("{'" + str(self) + "':'redacted'}")
            msg = msg.replace("'", '"', 10)
            msg = msg.encode()
            self.attrs = fernet.encrypt(msg)
            self.decodedattrs = 'showme' 
            self.save()
        except KeyError:
            pass


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
            #mindt = datetime.datetime.combine(datetime.date.min, datetime.time.min)
            #self.expires = mindt.replace(tzinfo=pytz.UTC)
            self.save()
            return str(self.token)
        else:
            return str('EXPIRED')

    def expire_token(self):
        mindt = datetime.datetime.combine(datetime.date.min, datetime.time.min)
        self.expires = mindt.replace(tzinfo=pytz.UTC)
        self.save()

    def get_created_time(self):
        return self.created

    def get_expiration_time(self):
        return self.expires

    def get_accessed_time(self):
        return self.accessed

    def set_expire_time(self, expires):
        self.expires = expires
        self.save()

    def get_renewal_time(self):
        return self.accessed

    def set_renewed(self, renewed):
        self.accessed = renewed
        self.save()

    def days_until_accessed(self):
        utcnow = datetime.datetime.utcnow()
        utcnow = utcnow.replace(tzinfo=pytz.UTC)
        utcnow = utcnow.replace(microsecond = 0)
        dta = self.get_accessed_time() - utcnow
        return str(dta)


class Connection(models.Model):
    name = models.CharField(max_length=150, default='setme')
    project = models.ForeignKey(Project, null=True, blank=True, on_delete=models.SET_NULL)
    attrsgroup = models.ForeignKey('sites.AttributeGroup', null=True, blank=True, on_delete=models.CASCADE, related_name='sites_Connection_attrsgroup')
    uniqueuser = models.ForeignKey('sites.Uniqueuser', null=True, blank=True, on_delete=models.CASCADE, related_name='sites_Connection_uniqueuser', verbose_name='Unique User')
    token = models.ForeignKey(AuthToken, null=True, blank=True, on_delete=models.SET_NULL)
    connection_state = models.CharField(max_length=50, null=True, default='setme', help_text=mark_safe(settings.HELP_CONNECTION_STATE))
    created = models.DateTimeField(auto_now_add=True)
    loggedout = models.DateTimeField(default=now)

    def __str__(self):
        return str(self.project) + ' - ' + str(self.created)

    def get_fields(self):
        return [(field.name, getattr(self,field.name)) for field in Connection._meta.fields]

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

    def get_token(self):
            return str(self.token)

    def get_projectname(self):
            return str(self.project)

    def get_uniqueusername(self):
            return str(self.uniqueuser)

    def get_connection_state(self):
            return str(self.connection_state)

    def get_ca(self):
        ca = [] 
        for a in self.attrsgroup.get_attrs():
            ca.append(a.get_attributes())
        return ca

    def get_request_attributes(self):
        attributes = []
        for ca in self.get_ca():
            attributes.append(ca)
        return attributes

    def get_ua(self):
        ua = [] 
        for a in self.uniqueuser.get_attributes():
            ua.append(a.get_attributes())
        return ua

    def get_user_attributes(self):
        attributes = []
        for ua in self.get_ua():
            attributes.append(ua)
        return attributes

    def show_user_attributes(self):
        attributes = []
        fernet = Fernet(settings.DATA_AT_REST_KEY_ATTRS)
        for ua in self.get_ua():
            dataatrest = bytes_in_string(ua)
            decoded_attrs = fernet.decrypt(dataatrest).decode()

            ale = ast.literal_eval(decoded_attrs)
            for k in ale.keys():
                attributes.append((str(k), ale[k]))
        return attributes

    def show_request_attributes(self):
        fernet = Fernet(settings.DATA_AT_REST_KEY_ATTRS)
        ca = self.get_ca() 
        decoded_attrs = fernet.decrypt(ca).decode()

        attributes = []
        ale = ast.literal_eval(decoded_attrs)
        for k in ale.keys():
            attributes.append((str(k), str(ale[k])))
        attributes.append(('data at rest', str(attrs)))
        return attributes


class Uniqueuser(models.Model):
    name = models.CharField(max_length=150, default='setme')
    fingerprint = models.CharField(max_length=150, default='setme')
    nameattrsgroup = models.ForeignKey('sites.AttributeGroup', null=True, blank=True, on_delete=models.CASCADE, related_name='Uniqueuser_nameattrsgroup')
    connattrsgroups = models.ManyToManyField('sites.AttributeGroup', related_name='uniqueuser_connattrsgroups')
    decodedallattrs = models.TextField(default='showme')
    decodednameattrs = models.TextField(default='showme')
    decodedconnattrs = models.TextField(default='showme')
    created = models.DateTimeField(auto_now_add=True)
    graphnode = models.ForeignKey('sites.GraphNode', null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        verbose_name = "Unique User"

    def get_fields(self):
        return [(field.name, getattr(self,field.name)) for field in Uniqueuser._meta.fields]

    def __str__(self):
        return self.name

    def graph_node_id(self):
        nid = str(-1)
        if self.graphnode is not None:
            nid = self.graphnode.nid()
        return nid

    def initstate(self):
        need_to_save = False
        if 'setme' in self.get_fingerprint() or 'showme' in str(self.clearallattrs()):
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
                self.decodedallattrs = str(da)
                self.decodednameattrs = str(uu)
            
            #try:
            #    if len(da['simplestring']) > int(0):
            #        da['simplestring'].sort()
            #except KeyError:
            #    pass

            msg = "    initstate uu: " + str(uu)
            logger.info(msg)
            self.fingerprint = hash_to_fingerprint(uu)
            msg = "    self.fingerprint: " + str(self.fingerprint)
            logger.info(msg)
            need_to_save = True 

        if 'showme' in str(self.clearconnattrs()):
            ca = {} 
            if self.connattrsgroups is not None:
                for ag in self.connattrsgroups.get_queryset():
                    for fp in ag.get_attrs():
                        attrs = get_attributesFromFp(str(fp))
                        if len(str(attrs)) > int(9) and str(attrs).startswith('{'):   # minimum str(ca) == '{"k":"v"}'
                            at = ast.literal_eval(attrs)
                            for k in at.keys(): 
                                ca[k] = at[k]
                        else:
                            try:
                                test = ca['simplestring']
                            except KeyError:
                                ca['simplestring'] = []
                            ca['simplestring'].append(str(attrs))
                #if settings.DEBUG:
                if True:
                    self.decodedconnattrs = str(ca)
                else:
                    self.decodedconnattrs = "Decoded attributes not available."

            castr = ':'
            try:
                if len(ca) > int(1):
                    allkeys = []
                    for k in ca.keys():
                        allkeys.append(k)
                    if len(allkeys) > int(1):
                        allkeys.sort()
                    castr = ':'
                    for k in allkeys:
                        castr = str(k) + astr
            except KeyError:
                pass
            enca = str(castr).encode()
            need_to_save = True 

        return need_to_save

    def save(self, *args, **kwargs):
        super(Uniqueuser, self).save(*args, **kwargs)
        if self.initstate():
            super(Uniqueuser, self).save(*args, **kwargs)

    def get_fingerprint(self):
        return str(self.fingerprint)

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
        at = [(None, ['none'])]
        if self.connattrsgroups is not None:
            at = []
            for ag in self.connattrsgroups.get_queryset():
                alist = []
                for a in ag.attrs.get_queryset():
                    alist.append(str(a))
                at.append((str(ag), str(alist)))
        return str(at)


class Organization(models.Model):
    name = models.CharField(max_length=50, null=True, default='unknownOrganization')
    projects = models.ManyToManyField(Project, related_name='organization_projects')
    updated = models.DateTimeField(auto_now_add=True)
    graphnode = models.ForeignKey('sites.GraphNode', null=True, blank=True, on_delete=models.SET_NULL)
    parent = models.ForeignKey('sites.Organization', null=True, blank=True, on_delete=models.CASCADE, related_name='organization_parent')

    class Meta:
        verbose_name = 'Organization'
        verbose_name_plural = 'Organization'

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

    def get_fields(self):
        retlist =  []
        for field in Organization._meta.fields:
            k = field.name
            v = getattr(self,field.name)
            if v is None:
                v = "None"
            if str(k) == 'updated':
                v = str(v)
            retlist.append((k,v))
        retlist.append(("Projects", self.current_projects()))
        return retlist

    def users(self):
        users = []
        #msg = str(self.projects.get_queryset())
        #logger.info(msg)
        for p in self.projects.get_queryset():
            users.append(p.users())
        if len(users) > int(1):
            users.sort()
        return users

    def contact_emails(self):
        users = []
        for a in self.userlist.get_queryset():
            users.append(str(a.email))
        return str(users)


class AttributeGroup(models.Model):
    name = models.CharField(max_length=150, default='setme')
    grouptype = models.ForeignKey('sites.NodeType', null=True, blank=True, on_delete=models.CASCADE)
    attrs = models.ManyToManyField(Attributes, related_name='AttributeGroup_attrs', verbose_name='Attrs')
    decodedattrs = models.TextField(default='showme')
    #graphnode = models.ForeignKey('sites.GraphNode', null=True, blank=True, on_delete=models.SET_NULL)

    def __str__(self):
        return self.name

    def get_fields(self):
        retlist =  []
        for field in AttributeGroup._meta.fields:
            k = field.name
            v = getattr(self,field.name)
            if v is None:
                v = "None"
            if str(k) == 'updated':
                v = str(v)
            retlist.append((k,v))
        return retlist

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

        if 'showme' in self.decodedattrs:
            if self.attrs is not None:
                dattrs = "Decoded attributes not available."
                #if settings.DEBUG:
                if True:
                    dattrs = ''
                    for a in self.get_attrs():
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
        for a in self.get_attrs():
            msg = msg + str(a) + ', '
        if msg.endswith(', '):
            msg =  msg[:-2]
        return msg

    def clearattrs(self):
        return self.decodedattrs 


class GraphNode(models.Model):
    name = models.CharField(max_length=150, default='setme')
    projectname = models.CharField(max_length=150, default='')
    nodeid = models.IntegerField(default='-1')
    nodetype = models.ForeignKey('sites.NodeType', null=True, blank=True, on_delete=models.CASCADE)

    def __str__(self):
        return str(self.name)

    def get_fields(self):
        return [(field.name, getattr(self,field.name)) for field in GraphNode._meta.fields]

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

    def get_fields(self):
        return [(field.name, getattr(self,field.name)) for field in NodeType._meta.fields]

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

    def get_fields(self):
        return [(field.name, getattr(self,field.name)) for field in Browser._meta.fields]

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
    name = models.CharField(max_length=150, default='setme', help_text=mark_safe(settings.HELP_DECRYPT_KEY_NAME))
    decrypt_key = models.CharField(default='setme', max_length=200, verbose_name='Decryption key', help_text=mark_safe(settings.HELP_DECRYPT_KEY))

    def __str__(self):
        return self.name

    def get_fields(self):
        return [(field.name, getattr(self,field.name)) for field in Key._meta.fields]

    def get_key(self):
        return self.decrypt_key

    def initstate(self):
        need_to_save = False
        if 'setme' in str(self.name):
            self.name = secrets.token_urlsafe(10)
            need_to_save = True
        #if len(self.decrypt_key) < int(6):
        if 'setme' in str(self.decrypt_key):
            self.decrypt_key = Fernet.generate_key().decode()
            need_to_save = True
        return need_to_save

    def save(self, *args, **kwargs):
        super(Key, self).save(*args, **kwargs)
        if self.initstate():
           super(Key, self).save(*args, **kwargs)


def email_from_ICAM_groupname(groupname):
    groupname = str(groupname).split(',')[0]
    if "=" in str(groupname):
        groupname = groupname.split('=')[1]
    email = None
    qr = GSL_ICAM_group.objects.filter(name=groupname)
    if qr.count() == int(1):
        email = str(qr[0].email)

    if email is None:
        email = "none.its"
        groupname = groupname.replace('ESRL ', '')
        qr = GSL_ICAM_group.objects.filter(name=groupname)
        if qr.count() == int(1):
            email = str(qr[0].email)
    return email

def is_user_a_sysad(**kwargs):
    user = kwargs['user']

    try:
        homeorg = kwargs['request'].session['samlUserdata']['LineOffice'][0]
    except KeyError:
        homeorg = 'ITS' 

    orglist = [] 
    orglist.append(settings.NONE_NAME)
    orglist.append('NOAA')
    orglist.append('GSL')
    orglist.append(str(homeorg))


    oukeylist = []
    keys = kwargs['request'].session['samlUserdata'].keys()
    for k in kwargs['request'].session['samlUserdata'].keys():
        if str(k).startswith('ou'):
            oukeylist.append(str(k))
    if len(oukeylist) > int(1):
        oukeylist.sort()
    oukeylist = ['ou0', 'ou1', 'ou2']
    for k in oukeylist:
        orglist.append(kwargs['request'].session['samlUserdata'][str(k)][0])
    get_or_add_sysadmin(user, homeorg, orglist)

class Sysadmin(models.Model):
    """
    A system administrator belongs to one or more organizations, one of which is designated as their primary.
    An administrator maybe designated as a superuser, with full administrative privileges
    """
    username = models.OneToOneField(User, null=True, on_delete=models.CASCADE)
    organizations = models.ManyToManyField('Organization', verbose_name='Organizations')
    organization = models.ForeignKey('Organization', default=1, related_name='sysadmin_organization',
                                     verbose_name='Primary Organization', on_delete=models.CASCADE)

    class Meta:
        unique_together = ['username', 'organization']

    def get_fields(self):
        return [(field.name, getattr(self,field.name)) for field in Sysadmin._meta.fields]

    def __str__(self):
        return str(self.username)

    def get_organizations(self):
        return self.organizations.get_queryset()

    def get_home_organization(self):
        return self.organization

    def organizations_list(self):
        orgs = []
        for o in self.organizations.get_queryset():
            orgs.append(str(o))
        return orgs

    def organizations_id_list(self):
        orgids = []
        for o in self.organizations.get_queryset():
            orgids.append(int(o.id))
        return orgids


class SSOObj(models.Model):
    ssostr = models.CharField(max_length=300, default='no-ssostr', help_text=mark_safe(settings.HELP_SSOSTR))
    email = models.EmailField(unique=True, null=True, blank=settings.NONE_EMAIL)
    icamattrs = models.TextField(max_length=8192, null=True, verbose_name="ICAM Attributes", default='{}', help_text=mark_safe(settings.HELP_ICAM_ATTRIBUTES))
    class Meta:
        verbose_name = 'SSO Object'

    def __str__(self):
        return str(self.email) 

    def get_email(self):
        return str(self.email) 

    def get_icamattrs(self):
        return self.icamattrs

@receiver(user_has_authenticated)
def post_auth_user_has_authenticated(sender, **kwargs):
    now = datetime.datetime.utcnow()
    msg = str(now) + ":post_auth_user_has_authenticated:" + str(kwargs['user'].username)
    logger.info(msg)
    is_user_a_sysad(**kwargs)
    user_has_authenticated_sendemail(**kwargs)

@receiver(user_login_failure)
def post_auth_user_login_failure(sender, **kwargs):
    now = datetime.datetime.utcnow()
    try:
        username = kwargs['user']
    except AttributeError:
        username = 'None'
    msg = str(now) + ":post_auth_user_login_failure = " + str(username)
    logger.info(msg)
    #user_has_login_failure_sendemail(**kwargs)

@receiver(user_logged_out)
def post_auth_user_has_logged_out(sender, **kwargs):
    now = datetime.datetime.utcnow()
    msg = str(now) + ":post_auth_user_has_logged_out = " + str(kwargs['user'].username)
    logger.info(msg)

#@receiver(user_cannot_authenticate)
#def post_auth_user_not_authenticated(sender, **kwargs):
#    now = datetime.datetime.utcnow()
#    msg = str(now) + ":post_auth_user_cannot_authenticate = " + str(kwargs['user'].username)
#    logger.info(msg)
#    #user_has_authenticated_sendemail(**kwargs)


@receiver(local_user_has_authenticated)
def post_auth_local_user_has_authenticated(sender, **kwargs):
    now = datetime.datetime.utcnow()
    msg = str(now) + ":post_auth_local_user_has_authenticated = " + str(kwargs['user'].username)
    logger.info(msg)
    user_has_authenticated_sendemail(**kwargs)


@receiver(local_user_password_rejected)
def post_auth_local_user_password_rejected(sender, **kwargs):
    now = datetime.datetime.utcnow()
    msg = str(now) + ":post_auth_local_user_password_rejected = " + str(kwargs['user'].username)
    logger.info(msg)
    #local_user_has_authenticated_sendemail(**kwargs)

@receiver(local_user_cannot_authenticate)
def post_auth_user_not_authenticated(sender, **kwargs):
    now = datetime.datetime.utcnow()
    msg = str(now) + ":post_auth_local_user_cannot_authenticate = " + str(kwargs['user'].username)
    logger.info(msg)
    #local_user_has_authenticated_sendemail(**kwargs)

def user_has_authenticated_sendemail(**kwargs):
    hl = hashlib.sha256()
    hl.update(str(kwargs['request'].COOKIES['csrftoken']).encode('utf-8'))
    hashedtoken = hl.hexdigest()
    existingtoken = 'none'

    fname = 'uploads/ssopuid_' + str(kwargs['user'].id) + '.txt'
    try:
        if os.path.exists(fname):
            fh = open(fname, 'r')
            existingtoken = fh.read()
        else:
            fh = open(fname, 'w')
            fh.write(hashedtoken)
        fh.close()
    except OSError as e:
        print('failed to create or read token file ' + str(fname) + '  error = ' + str(e))

    if hashedtoken != existingtoken:
        email = kwargs['user'].email
        firstname = kwargs['user'].first_name
        ymdhms = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        subject = settings.USER_HAS_AUTHENTICATED_SUBJECT
        body = settings.USER_HAS_AUTHENTICATED_BODY
        body = body.replace( 'firstname', firstname )
        body = body.replace( 'ymdhms', ymdhms )
   
        fromaddr = settings.EMAIL_HOST_USER
        toaddr = [email]
        try:
            if settings.DEBUG_VERBOSE:
                msg = "DEBUG -- running: send_mail(subject, body, fromaddr, toaddr, fail_silently=False)"
                msg = msg + ' -- toaddr: ' + str(toaddr)
                msg = msg + ' -- fromaddr: ' + str(fromaddr)
                msg = msg + ' -- subject: ' + str(subject)
                logger.info(msg)
            send_mail(subject, body, fromaddr, toaddr, fail_silently=False)
        except Exception as e:
            now = datetime.datetime.utcnow()
            msg = str(now) + ":User has logged in email failed:" + str(email) + ":post_auth_user_has_authenticated:" + str(e)
            logger.info(msg)


STATE_CHOICES = [('Normal', 'Normal operations'), ('Bypass', 'EPO bypass')]
class Room(models.Model):
    number = models.CharField(max_length=150, default='number')
    name = models.CharField(max_length=150, default='name')
    current_state = models.CharField(max_length=150, choices=STATE_CHOICES)

    def __str__(self):
        return self.number

    def get_fields(self):
        return [(field.name, getattr(self,field.name)) for field in Room._meta.fields]

    def fullname(self):
        return self.number + ' (' + self.name + ')'

    def mode(self):
        return self.current_state

    def colors(self):
        if 'normal' in str(self.mode()).lower():
           # light green used by NCO
           colors = ('black', '#e7f4e4')
        else:
           colors = ('white', 'red')
        return colors


def send_removal_notice_email(kwargs):
    #msg = "\n\n\nsend_removal_notice_email:\n"
    #logger.info(msg)

    email = kwargs['user'].email
    firstname = kwargs['user'].firstname
    last_connected_datetime = str(kwargs['lcdt'])
    expires_datetime = str(kwargs['expires_datetime'])
    warned_datetime = str(kwargs['warned_datetime'])
    removed_in_dtdelta = str(kwargs['removed_in_dtdelta'])
    body_comment = str(kwargs['body_comment'])
    renewal_token = str(kwargs['renewal_token'])
    ymdhms = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    subject = settings.USER_REMOVAL_NOTICE_SUBJECT

    projects = {}
    #msg = "   email: " + str(email)
    #logger.info(msg)
    for p in Project.objects.all():
        if str(p).lower().startswith(settings.NONE_NAME):
            continue
        if p.authorized({"email": email}):
            if not p.name.startswith('demo') and not p.name.startswith('showattr'):
                try:
                    test = projects[str(p)]
                except KeyError:
                    projects[str(p)] = {}
                projects[str(p)]['link'] = settings.LDG_BASE + 'ldg/' + p.name
                projects[str(p)]['owner'] = str(p.owner)
    project_list = []
    project_names = []
    bcc = []
    for k in projects.keys():
        project_names.append(str(k))
    if len(project_names) > int(1):
       project_names.sort()
    info = '\n'
    for n in project_names:
        info = info + '    ' + str(n) + " at " + str(projects[n]['link']) + ' owned by ' + str(projects[n]['owner']) + '\n'
        bcc.append(str(projects[n]['owner']))
    project_list = info 

    renewal_link = settings.EXTERNAL_URL + 'sites/renew/' + str(renewal_token)
    remove_account_link = settings.EXTERNAL_URL + 'sites/remove/' + str(renewal_token)

    body = settings.USER_REMOVAL_NOTICE_BODY
    body = body.replace( 'firstname', firstname )
    body = body.replace( 'ymdhms', ymdhms )
    body = body.replace( 'last_connected_datetime', last_connected_datetime )
    body = body.replace( 'project_list', project_list )
    body = body.replace( 'renewal_link', renewal_link )
    body = body.replace( 'remove_account_link', remove_account_link )
    body = body.replace( 'body_comment', body_comment )
    body = body.replace( 'removed_in_dtdelta', removed_in_dtdelta )
    body = body.replace( 'expires_datetime', expires_datetime )
    body = body.replace( 'warned_datetime', warned_datetime )

    fromaddr = settings.EMAIL_HOST_USER
    toaddr = [email]
    try:
        SEND_EMAIL = False
        if settings.DEBUG:
            if str(email) in str(settings.EMAIL_TEST_USERS):
                #msg = "    send_mail(subject, body, fromaddr, toaddr, bcc=bcc, fail_silently=False)"
                #msg = msg + ' -- toaddr: ' + str(toaddr)
                #msg = msg + ' -- fromaddr: ' + str(fromaddr)
                #msg = msg + ' -- subject: ' + str(subject)
                #msg = msg + ' -- body: ' + str(body)
                #logger.info(msg)
                SEND_EMAIL = True 
       
        if SEND_EMAIL:
            emailmessage = EmailMessage(subject, body, fromaddr, toaddr, bcc)
            emailmessage.send(fail_silently=False)
            #send_mail(subject, body, fromaddr, toaddr, bcc=bcc, fail_silently=False)
            #msg = '           renewal_link: ' + str(renewal_link)
            #logger.info(msg)
            #msg = '           remove_account_link: ' + str(remove_account_link)
            #logger.info(msg)
        #else:
        #    msg = "DEBUG -- NOT running: send_mail(subject, 'BODY', fromaddr, toaddr, bcc=bcc, fail_silently=False)"
        #    logger.info(msg)
    except Exception as e:
        now = datetime.datetime.utcnow()
        msg = str(now) + ":send_removal_notice_email failed for:" + str(email) + ":" + str(e)
        logger.info(msg)

