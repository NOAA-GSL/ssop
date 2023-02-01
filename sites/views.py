import ast
import jwt
from hashlib import md5
import os
import sys
import requests
import secrets
import datetime
import pytz
import subprocess
import logging
import pprint
import networkx as nx
import matplotlib.pyplot as plt

from ssop import settings
from django.http import HttpResponse, HttpResponseRedirect, response
from django.shortcuts import redirect, render
from django.contrib.auth.models import User
from cryptography.fernet import Fernet

from sites.forms import ProjectForm
from sites.models import Attributes, AttributeGroup, AuthToken, GraphNode, NodeType, Connection, Project, Uniqueuser 

logger = logging.getLogger('ssop.models')


class Lmr():
    idx = int(0)
    tags = ['left', 'middle', 'right']

    def next(self):
        idx = self.get_idx()
        if idx > int(2):
            self.idx = int(0)
            idx = int(0) 
        else:
            self.idx = idx + int(1)
        return self.tags[idx]

    def get_idx(self):
        return self.idx


def runcmdl(cmdl, execute):
    """
    prints cmdl or passes it to subprocess.run if execute is True
    returns status, result as strings
    """
    cmd = " ".join(cmdl)
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
    else:
        status = int(-1)
        result = "     cmd: " + str(cmd)
    return status, result


def x509oneline(x509):
    oneline = ''
    for line in x509.split('\n'):
        if 'BEGIN' in line or 'KEY' in line or 'END' in line:
            continue
            oneline = oneline + line
    return oneline


def ldg(request, project_name = None):

    if settings.VERBOSE:
        msg = "   ldg request: " + str(request)
        logger.info(msg)
        msg = "   ldg project_name: " + str(project_name)
        logger.info(msg)

    if project_name is None:
        project_name = 'SSOP'
        msg = "   ldg project_name is now: " + str(project_name)
        logger.info(msg)

    project_state = settings.LOGINDOTGOV_LOGIN_STATE
    if project_name:
        qs = Project.objects.filter(name=project_name)
        if qs.count() == int(1):
            qs = qs[0]
            msg = "   ldg project_name: " + str(project_name)
            project_state = qs.get_connection_state()
        else:
            error_msg = "Sorry, project " + str(project_name) + " was not found."
            attributes = []
            lmr = Lmr()
            for p in Project.objects.all():
                src = '/ssop/static/projects/' + str(p) + '/logo'
                link = 'https://gsl.noaa.gov/ssop/ldg/' + str(p)
                linktext = p.get_verbose_name()
                alt = 'Logo for project ' + str(p)
                attributes.append((str(p), link, linktext, src, alt, lmr.next()))
            msg = "   attributes: " + str(attributes)
            logger.info(msg)
            return render(request, 'sites_grid.html', {'attributes': attributes, 'error_msg': error_msg})

    if 'ldg' in str(request):

        login = 'https://idp.int.identitysandbox.gov/openid_connect/authorize?'
        login = login + "acr_values=" + settings.LOGINDOTGOV_ACR + "&"
        login = login + "client_id=" + settings.LOGINDOTGOV_CLIENT_ID + "&"
        login = login + "nonce=" + str(secrets.token_urlsafe(30)) + "&"
        login = login + "prompt=select_account&"
        login = login + "redirect_uri=" + settings.LOGINDOTGOV_RETURN_TO + "&"
        login = login + "response_type=code&"
        login = login + "scope=" + settings.LOGINDOTGOV_SCOPE + "&"
        login = login + "state=" + project_state 

        if settings.VERBOSE:
            msg = '   ldg login HttpResponseRedirect( ' + str(login) + ' )'
            logger.info(msg)

        return HttpResponseRedirect(login)
    else:
         HttpResponseRedirect(settings.LOGINDOTGOV_ERROR_REDIRECT)

def uuFromFp(fingerprint, nameattrsgroup, connattrsgroup):
    qs = Uniqueuser.objects.filter(fingerprint=fingerprint)
    if qs.count() == int(0):
        uu = Uniqueuser(fingerprint=fingerprint, nameattrsgroup=nameattrsgroup, connattrsgroup=connattrsgroup)
        uu.save()
        msg = "   created uniqueuser " + str(uu) + " with fingerprint " + str(fingerprint)
        msg = msg + " , nameattrsgroup " + str(nameattrsgroup) + " and connattrsgroup " + str(connattrsgroup)
        logger.info(msg)
    else:
        uu = qs[0]
        msg = "   found uniqueuser " + str(uu)
        msg = "   fingerprint: " + str(uu.fingerprint)
        msg = msg + " , nameattrsgroup " + str(uu.nameattrsgroup) + " and connattrsgroup " + str(uu.connattrsgroup)
        logger.info(msg)
    return uu 

def attributesFromDecodedFp(decodedfingerprint, encrypted_attrs):
    qs = Attributes.objects.filter(decodedfingerprint=decodedfingerprint)
    if qs.count() == int(0):
        attrs = Attributes(attrs=encrypted_attrs, decodedfingerprint=decodedfingerprint)
        attrs.save()
    else:
        attrs = qs[0]
    return attrs

def attributeGroupFromAttributes(grouptype, attributelist):
    msg = "   aGFA attributelist: " + str(attributelist) + " for grouptype " + str(grouptype)
    logger.info(msg)

    #qs = None
    #for attr in attributelist:
    #    alist = list(AttributeGroup.objects.filter(attrs=attr))
    #    msg = "   alist: " + str(alist)
    #    logger.info(msg)
    #    qs = AttributeGroup.objects.filter(attrs__in=alist)

    #if qs is None:
    #    msg = "  no qs!...."
    #    logger.info(msg)

    qs = AttributeGroup.objects.filter(grouptype=grouptype, attrs__in=attributelist)
    if qs.count() == int(0):
        attrsgroup = AttributeGroup(grouptype=grouptype)
        attrsgroup.save()
        msg = "   created attrsgroup: " + str(attrsgroup)
    else:
        msg = "qs.count = " + str(qs.count())
        logger.info(msg)
        attrsgroup = qs[0]
        msg = "   fetched first attrsgroup: " + str(attrsgroup)
    logger.info(msg)

    for a in attributelist:
        #msg = "   append a: " + str(a)
        #logger.info(msg)
        attrsgroup.attrs.add(a)
    return attrsgroup


def test_attributeGroupFromAttributes(grouptype, attributelist):
    msg = "   test aGFA attributelist: " + str(attributelist)
    logger.info(msg)

    qs = None
    for attr in attributelist.get_attrs():
        alist = list(Attributes.objects.filter(attrs=attr))
        msg = "   alist for " + str(attr) + " is: " + str(alist)
        logger.info(msg)

    qs = AttributeGroup.objects.filter(grouptype=grouptype, attrs__in=attributelist)
    if qs.count() == int(0):
        attrsgroup = AttributeGroup(grouptype=grouptype, attrs__in=attributelist)
        attrsgroup.save()
        msg = "   created attrsgroup: " + str(attrsgroup) + " with grouptype " + str(grouptype)
    else:
        msg = "qs.count = " + str(qs.count())
        logger.info(msg)
        attrsgroup = qs[0]
        msg = "   fetched first attrsgroup: " + str(attrsgroup)
    logger.info(msg)

    for a in attributelist:
        #msg = "   append a: " + str(a)
        #logger.info(msg)
        attrsgroup.attrs.add(a)
    return attrsgroup

def initialize_nodetypes():
    qs = NodeType.objects.all()
    if qs.count() < len(settings.NODE_TYPE_CHOICES):
        for t in settings.NODE_TYPE_CHOICES:
            nt = NodeType(type=t)
            nt.save()

def ldg_authenticated(request):

    attributes = []
    #requestattrs = None
    #userattrs = None
    connattrsgroup = None
    connattrslist = []
    uuattrslist = []
    initialize_nodetypes()
    try:
        conngrouptype = NodeType.objects.filter(type='Conngroup').first()
        namegrouptype = NodeType.objects.filter(type='Namegroup').first()

        fernet = Fernet(settings.DATA_AT_REST_KEY_ATTRS)

        realip = str(request.headers['X-Real-Ip']).encode()
        realipfp = md5(realip).hexdigest()
        encrypted_realip = fernet.encrypt(realip)
        realipattrs = attributesFromDecodedFp(realipfp,  encrypted_realip)

        xff = str(request.headers['X-Forwarded-For']).encode()
        xfffp = md5(xff).hexdigest()
        encrypted_xff = fernet.encrypt(xff)
        xffattrs = attributesFromDecodedFp(xfffp, encrypted_xff)

        sechua = str(request.headers['Sec-CH-UA']).encode()
        sechuafp = md5(sechua).hexdigest()
        encrypted_sechua = fernet.encrypt(sechua)
        sechuaattrs = attributesFromDecodedFp(sechuafp, encrypted_sechua)

        ua = str(request.headers['User-Agent']).encode()
        uafp = md5(ua).hexdigest()
        encrypted_ua = fernet.encrypt(ua)
        uaattrs = attributesFromDecodedFp(uafp, encrypted_ua)

        connattrslist.append(realipattrs)
        if xffattrs != realipattrs:
            connattrslist.append(xffattrs)
        connattrslist.append(sechuaattrs)
        connattrslist.append(uaattrs)
        connattrsgroup = attributeGroupFromAttributes(conngrouptype, connattrslist)
        # needed by uu so browser info can be tracked
        #for a in attrslist:
        #    uuattrslist.append(a)

        rh = []
        rh.append(('xri', str(realipattrs)))
        if xffattrs != realipattrs:
            rh.append(('xff', str(xffattrs)))
        rh.append(('scu', str(sechuaattrs)))
        rh.append(('ua', str(uaattrs)))

        #msg = "   rh: " + str(rh)
        #logger.info(msg)
        rhstr = str(rh).encode()
        #msg = "   rhstr: " + str(rhstr)
        #logger.info(msg)
        fingerprint = md5(rhstr).hexdigest()
        #msg = "   fingerprint: " + fingerprint
        #logger.info(msg)
        rhstr = str(rh).encode()
        encrypted_rh = fernet.encrypt(rhstr)
        #msg = "   fingerprint: " + fingerprint
        #logger.info(msg)
        #requestattrs = attributesFromDecodedFp(fingerprint, encrypted_rh)

    except KeyError:
        msg = "   NO request.headers found"
        logger.info(msg)

    if settings.VERBOSE:
        msg = "   ldg_authenticated request: " + str(request)
        logger.info(msg)

    state = None
    project_state = settings.LOGINDOTGOV_LOGIN_STATE
    # first 10 digits of start the are utc seconds
    connection_state = '1234567890' + project_state
    if 'code' in str(request):
        try:
            code = request.GET['code']
            state = request.GET['state']
            if settings.VERBOSE:
                msg = "   code: " + code
                logger.info(msg)
                msg = "   state: " + state
                logger.info(msg)
        except KeyError:
            msg = "    KeyError request.session: " + str(request)
            logger.info(msg)

    ERROR_REDIRECT = settings.LOGINDOTGOV_ERROR_REDIRECT
    RETURN_TO = None

    project = None 
    qs = Project.objects.filter(state=state[10:])
    if qs.count() == int(1):
        qs = qs[0]
        project = qs
        connection_state = project.get_connection_state()
        attributes.append(('name', qs.name))
        return_to = qs.get_returnto()
        error_redirect = qs.get_err_redirect()
        if not 'SSOP' in str(project):
            ERROR_REDIRECT = error_redirect 
            RETURN_TO = return_to
        attributes.append(('return_to', return_to))
        attributes.append(('error_redirect', error_redirect))
        attributes.append(('state', state))

    if settings.VERBOSE:
        msg = "    state: " + str(state)
        logger.info(msg)

        msg = "    RETURN_TO = " + str(RETURN_TO)
        logger.info(msg)

    # disregard first 10 chars -- which are UTC seconds
    if str(connection_state[10:]) in str(state):
        tokenurl = settings.LOGINDOTGOV_IDP_SERVER + "/api/openid_connect/token"

        expires = int(datetime.datetime.utcnow().strftime('%s')) + int(settings.JWTEXP)

        assertion = {}
        assertion["iss"] = str(settings.LOGINDOTGOV_CLIENT_ID)
        assertion["sub"] = str(settings.LOGINDOTGOV_CLIENT_ID)
        assertion["aud"] = str(tokenurl)
        assertion["jti"] = str(secrets.token_urlsafe(settings.JWTSAFELEN))
        assertion["exp"] = str(expires)

        if settings.VERBOSE:
            msg = "   assertion: " + str(assertion)
            logger.info(msg)

        signedassertion = jwt.encode(assertion, settings.LOGINDOTGOV_PRIVATE_CERT, algorithm="RS256")  
        data = "client_assertion_type=" + settings.LOGINDOTGOV_CLIENT_ASSERTION_TYPE + "&"
        data = data + "client_assertion=" + str(signedassertion) + "&"
        data = data + "code=" + str(code) + "&"
        data = data + "grant_type=authorization_code"

        proxies = {}
        proxies["http"] = str(settings.HTTP_PROXY)
        proxies["https"] = str(settings.HTTP_PROXY)

        if settings.VERBOSE:
            msg = "   tokenurl: " + str(tokenurl)
            logger.info(msg)
            msg = "       data: " + str(data)
            logger.info(msg)

            curlcmd = 'curl -v -x ' + settings.HTTP_PROXY + ' -d "' + str(data) + '" ' + tokenurl
            logger.info(curlcmd)

        tokenresponse = requests.post(url=tokenurl, data=data, proxies=proxies)
        if settings.VERBOSE:
            msg = "   tokenresponse: " + tokenresponse.text
            logger.info(msg)

        ale = ast.literal_eval(tokenresponse.text)
        if settings.VERBOSE:
            msg = "  ale: " + str(ale)
            logger.info(msg)

        try:
            accesstoken = ale['access_token']
        except KeyError:
            accesstoken = None
        if settings.VERBOSE:
            msg = "  accesstoken: " + str(accesstoken)
            logger.info(msg)

        infourl = settings.LOGINDOTGOV_IDP_SERVER + "/api/openid_connect/userinfo"

        if settings.VERBOSE:
            # curl headers need str vs {} for requests.get
            cheaders = "Authorization: Bearer " + str(accesstoken)
            curlcmd = 'curl -v -x ' + settings.HTTP_PROXY + '  -H "' + cheaders + '" ' + infourl
            logger.info(curlcmd)

        headers = {}
        headers["Authorization"] = "Bearer " + str(accesstoken)
        userattributes = requests.get(infourl, proxies=proxies, headers=headers)

        attrs = {} 
        attstr = userattributes.text
        if settings.VERBOSE:
            msg = "   attstr: " + attstr
            logger.info(msg)
  
        uu = {} 
        for attr in attstr.split(','):
            attr = attr.replace('{', '')
            attr = attr.replace('}', '')
            #msg = "   attr = " + str(attr)
            #logger.info(msg)

            v = str(attr).split(':')
            #msg = "    v = " + str(v)
            #logger.info(msg)

            key = str(v[0]).replace('"', '', 10)
            value = str(v[1]).replace('"', '', 10)
            if len(v) > int(2):
                value = value + ':' + str(v[2]).replace('"', '', 10)
            attributes.append((key, str(value)))
            attrs[key] = value

            if 'sub' in str(key) or 'email' in str(key):
                uu[key] = value

            data = {}
            data[key] = value 
            data = str(data).encode()
            fingerprint = md5(data).hexdigest()
            encrypted_attrs = fernet.encrypt(data)
            thisattr = attributesFromDecodedFp(fingerprint,  encrypted_attrs)
            uuattrslist.append(thisattr)

        #connattrsgroup = attributeGroupFromAttributes(conngrouptype, connattrslist)
        nameattrsgroup = attributeGroupFromAttributes(namegrouptype, uuattrslist)
        enuu = str(uu).encode()
        #msg = "    enuu = " + str(enuu)
        #logger.info(msg)
        uufp = md5(enuu).hexdigest()
        #msg = "    uufp = " + str(uufp)
        #logger.info(msg)

        uniqueuser = uuFromFp(uufp, nameattrsgroup=nameattrsgroup, connattrsgroup=connattrsgroup)
        authtoken = AuthToken()
        authtoken.save()

        connection = Connection(project=project, attrsgroup=connattrsgroup, token=authtoken, connection_state=connection_state, uniqueuser=uniqueuser)
        connection.save()

        # update the connections map
        #(imageattributes, debugprint) = make_connections_by_project_img()
        if settings.VERBOSE:
            msg = "    authtoken: " + str(authtoken)
            logger.info(msg)
            msg = "    attributes: " + str(attributes)
            logger.info(msg)

        if RETURN_TO:
            request.session["Authorization"] = "Bearer " + str(authtoken)
            if project.append_access_token(): 
                return_to = RETURN_TO + "?access_token=" + str(authtoken)
            if settings.VERBOSE:
                msg = "    return_to: " + str(return_to)
                logger.info(msg)
            return HttpResponseRedirect(return_to)
        else:
            logouturl = 'https://gsl.noaa.gov/ssop/logout/' + str(connection_state)
            msg = "    logouturl: " + str(logouturl)
            logger.info(msg)
            return render(request, 'attrs.html', {'paint_logout': True, 'attributes': attributes, 'logouturl': logouturl})
    else:
        msg = " project_state " + str(connection_state) + " is not a logindotgov state: " + str(state)
        logger.info(msg)

    return HttpResponseRedirect(ERROR_REDIRECT)

def logout(request, connection_state = None):
    msg = "   logout request: " + str(request)
    logger.info(msg)
    msg = "   logout connection_state: " + str(connection_state)
    logger.info(msg)

    if 'logout' in str(request):
        qs = Connection.objects.filter(connection_state=connection_state)
        if qs.count() > int(0):
            qs = qs[0]
            now = datetime.datetime.utcnow()
            now = now.replace(tzinfo=pytz.UTC)
            qs.loggedout = now
            qs.save()

        logout = settings.LOGINDOTGOV_IDP_SERVER + '/openid_connect/logout?'
        logout = logout + "client_id=" + settings.LOGINDOTGOV_CLIENT_ID + "&"
        logout = logout + "post_logout_redirect_uri=" + settings.LOGINDOTGOV_LOGOUT_URI + "&"
        logout = logout + "state=" + connection_state 

        
        msg = '   logout HttpResponseRedirect( ' + str(logout) + ' )'
        logger.info(msg)
        return HttpResponseRedirect(logout)
    else:
        return HttpResponseRedirect("ssop/oops")

def oops(request):
    now = datetime.datetime.now()
    now = now.replace(tzinfo=pytz.UTC)
    html = "<html><body>Oops... It is now %s.</body></html>" % now
    return HttpResponse(html)
    
def indextable(request):
    msg = "   index request: " + str(request)
    logger.info(msg)

    attributes = []
    lmr = Lmr()
    for p in Project.objects.all().order_by('display_order'):
        if p.is_enabled():
            logo = '/ssop/static/projects/' + str(p) + '/logo'
            link = 'https://gsl.noaa.gov/ssop/ldg/' + str(p)
            linktext = p.get_verbose_name()
            attributes.append((str(p), link, linktext, logo, lmr.next()))
    return render(request, 'sites.html', {'attributes': attributes})

def index(request):
    msg = "   index request: " + str(request)
    logger.info(msg)

    attributes = []
    lmr = Lmr()
    for p in Project.objects.all().order_by('display_order'):
        if p.is_enabled():
            logo = '/ssop/static/projects/' + str(p) + '/logo'
            link = 'https://gsl.noaa.gov/ssop/ldg/' + str(p)
            linktext = p.get_verbose_name()
            alt = 'Logo for project ' + str(p)
            attributes.append((str(p), link, linktext, logo, alt, lmr.next()))
    return render(request, 'sites_grid.html', {'attributes': attributes, 'showplots': False})

#@ensure_csrf_cookie
def project_ldg(request, projectname):
    # create a form instance and populate it with data from the request:
    form = ProjectForm(request.POST)
    now = datetime.datetime.utcnow()

    # if this is a POST request we need to process the form data
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        creator = str(user)

        if user.is_authenticated:
            if form.is_valid():
                login(request, user)

                form.Meta.message = "hello " + str(user)
            else:
                msg = str(now) + ":formNotValid:" + str(user)
            logger.info(msg)
            form.Meta.message = msg
            return render(request, 'project_ldg.html', {'form': form})

        else:
            msg = str(now) + ":UserNotAuthenticated:" + str(user)
            form.Meta.message = msg
            return render(request, 'project_ldg.html', {'form': form})

    else:
        msg = str(now) + ":calledDeleteHostWithoutPOST:" + str(request.user)
        form.Meta.message = msg
        qs = Project.objects.filter(name=projectname)
        attributes = []
        if qs.count() == int(1):
            qs = qs[0]
            attributes.append(('name', qs.name))
            attributes.append(('return_to', qs.get_returnto()))
            attributes.append(('authenticated_redirect', qs.get_auth_redirect()))
            attributes.append(('error_redirect', qs.get_err_redirect()))
            attributes.append(('state', qs.get_state()))
            login = "https://gsl.noaa.gov/ssop/ldg/" + str(qs.name) + "/"
            return HttpResponseRedirect(login)

        else:
            msg = 'projectname ' + str(projectname) + ' not found'
            attributes.append(('error', msg))
        return render(request, 'project_ldg.html', {'form': form, 'paint_logout': True, 'attributes': attributes})
 
def getattrs(request, access_token = None):
    attributes = [('Attributes', 'unavailable')]
    project_state = settings.LOGINDOTGOV_LOGIN_STATE
    if access_token:
        qs = Connection.objects.filter(token=access_token)
        if qs.count() > int(0):
            qs = qs[0]
            token = qs.token.get_token()
            project_state = qs.project.get_state()
            if str(access_token) in str(token):
                attributes = qs.get_attributes()
            else:
                attributes = [('Attributes', 'tokenmismatch')]
                attributes.append(('access_token', 'access_token'))
                attributes.append(('token', 'token'))
        else:
            attributes = [('Attributes', 'no access_token')]
            attributes.append(('access_token', 'access_token'))

    return render(request, 'attrs.html', {'paint_logout': True, 'attributes': attributes, 'project_state': project_state})

def bytes_in_string(b):
        if str(b).startswith("b'"):
            return str(b)[2:-1]
        else:
            return b

def showattrs(request, access_token = None):
    attributes = [('Attributes', 'unavailable')]
    #msg = "    showattrs -- access_token = " + str(access_token)
    #logger.info(msg)

    if access_token:
        aqs = AuthToken.objects.filter(token=access_token)
        authtoken = None
        if aqs.count() > int(0):
            authtoken = aqs[0]
        cqs = Connection.objects.filter(token=authtoken)
        if cqs.count() > int(0):
            connection = cqs[0]
            if connection.project.expiretokens:           
                fetchedtoken = connection.token.get_token()
                if str(fetchedtoken) not in str(authtoken):
                    msg = "fetchedtoken not equal authtoken for " + str(fetchedtoken) + " and " + str(authtoken)
                    logger.info(msg)
            decode_key = connection.project.get_decode_key()
            decode_key_dar_key_attrs = settings.DATA_AT_REST_KEY_ATTRS

            user_attributes = connection.show_user_attributes()
            try:
                aledar = ast.literal_eval(user_attributes[0][1])
                dataatrest = bytes_in_string(aledar)
                attributes = []
            except KeyError:
                dataatrest = 'dataatrest'
            dataatrest = str(dataatrest).encode()
            msg = '   dataatrest: ' + str(dataatrest)
            logger.info(msg)

            #try:
            #    attributes.append(('request.headers', str(request.headers)))
            #except KeyError:
            #    pass
            attrs = {}
            for k,v in user_attributes:
                attrs[k] = v

            dit = Fernet(decode_key)
            data_in_transit = dit.encrypt(dataatrest)
            attributes.append(('dit', str(data_in_transit)))

            jwtdata = {}
            jwtdata['dit'] = str(data_in_transit)
            #msg = "   jwtdata: " + str(jwtdata)
            #logger.info(msg)

              
            jsonwebtoken = jwt.encode(jwtdata, settings.JWT_PRIVATE_KEY, algorithm="RS256")
            attributes.append(('json web token', jsonwebtoken))
            attrsjwt = "https://gsl.noaa.gov/ssop/sites/attrsjwt/" + str(access_token) + "/"
            attributes.append(('attrsjwt', attrsjwt))

        else:
            attributes = [('Attributes', 'tokenmismatch')]
            attributes.append(('access_token', access_token))
            attributes.append(('authtoken', authtoken))
    else:
        attributes = [('Attributes', 'no access_token')]
        attributes.append(('authtoken', authtoken))

    return render(request, 'attrs.html', {'paint_logout': True, 'attributes': attributes})

def attrsjwt(request, access_token = None):
    #msg = "   attrsjwt -- request = " + str(request)
    #logger.info(msg)
    #msg = "   attrsjwt -- access_token = " + str(access_token)
    #logger.info(msg)

    signedattributes = None
    if access_token:
        aqs = AuthToken.objects.filter(token=access_token)
        authtoken = None
        if aqs.count() > int(0):
            authtoken = aqs[0]
        cqs = Connection.objects.filter(token=authtoken)
        if cqs.count() > int(0):
            connection = cqs[0]

            # disabled for debugging -- remember it is a one time token
            #token = connection.token.get_token()
            if connection.project.expiretokens:           
                fetchedtoken = connection.token.get_token()
                if str(fetchedtoken) not in str(authtoken):
                    msg = "fetchedtoken not equal authtoken for " + str(fetchedtoken) + " and " + str(authtoken)
                    logger.info(msg)

            encode_key = connection.project.get_decode_key()
            user_attributes = connection.get_user_attributes()
            #msg = "    connection get_user_attributes(): " + str(user_attributes)
            #logger.info(msg)

            # attributes is a single element list containing tuple: ('user_attributes', {'simplestring': b'a-string-of-bytes'})
            dar = Fernet(settings.DATA_AT_REST_KEY_ATTRS)
            aledar = ast.literal_eval(user_attributes[0][1])
            dataatrest = bytes_in_string(aledar['simplestring'])
            msg = '   dataatrest: ' + str(dataatrest)
            logger.info(msg)

            decrypteddata = dar.decrypt(dataatrest).decode()
            msg = "   decrypteddata: " + str(decrypteddata)
            logger.info(msg)

            dit = Fernet(encode_key)
            data_in_transit = dit.encrypt(decrypteddata.encode())
            #attributes.append(('dit', str(data_in_transit)))
            #msg = "   data_in_transit: " + str(data_in_transit)
            #logger.info(msg)

            attrs = {}
            attrs['dit'] = str(data_in_transit)
            #for k,v in attributes:
            #    if 'dit' in str(k):
            #        attrs[k] = v 
            #        continue
            signedattributes = jwt.encode(attrs, settings.JWT_PRIVATE_KEY, algorithm="RS256")
            #msg = "   leaving attrsjwt -- access_token = " + str(access_token)
            #logger.info(msg)
            #msg = "   attrsjwt -- signedattributes = " + str(signedattributes)
            #logger.info(msg)
        else:
            msg = "  qscount is zero for access_token " + str(access_token)
            logger.info(msg)

    return render(request, 'signedattrs.html', {'attributes': signedattributes})


def demoapp_python(request):

    src = 'unable to read sites/demoapp_python.txt'
    with open(os.path.join(settings.BASE_DIR, 'sites/demoapp_python.txt')) as srcfile:
        src = srcfile.read()

    template = 'unable to read templates/demoapp.html'
    with open(os.path.join(settings.BASE_DIR, 'templates/demoapp.html')) as srcfile:
        template = srcfile.read()

    data = {}
    msg = "   demoapp request -- request = " + str(request)
    logger.info(msg)
    data['request'] = request 

    access_token = None
    if 'access_token=' in str(request):
        (junk, access_token) = str(request).split('=')
        access_token = access_token[:-2]
    msg = "   demoapp landing -- access_token = " + str(access_token)
    logger.info(msg)

    try:
        msg = "   request.headers = " + str(request.headers)
    except KeyError:
        msg = "   NO request.headers found"
    data['request.headers'] = msg 
    #logger.info(msg)
    try:
        msg = request.session["Authorization"]
    except KeyError:
        msg = "   NO request.session found"
    data['request.session'] = msg 

    # the trailing '/' is MANDATORY
    extattrsurl = "https://gsl.noaa.gov/ssop/sites/attrsjwt/" + str(access_token) + "/"
    #msg = "   external attrsurl: " + str(extattrsurl)
    intattrsurl = "https://gsl-webstage8.gsd.esrl.noaa.gov/ssop/sites/attrsjwt/" + str(access_token) + "/"
    #msg = "   internal attrsurl: " + str(intattrsurl)
    #logger.info(msg)

    # curl headers need str vs {} for requests.get
    cheaders = '"Authorization: Bearer ' + str(access_token) + '"'

    extcurl_cmdl = []
    extcurl_cmdl.append('/usr/bin/curl')
    extcurl_cmdl.append('-v')
    extcurl_cmdl.append('-x')
    extcurl_cmdl.append(settings.HTTP_PROXY)
    extcurl_cmdl.append('-H')
    extcurl_cmdl.append(cheaders)
    extcurl_cmdl.append('https://noaa.gov')
    #extcurl_cmdl.append(intattrsurl)

    extcurl = 'curl -v -x ' + settings.HTTP_PROXY + '  -H "' + cheaders + '" ' + intattrsurl
    #logger.info(extcurl)
    intcurl = 'curl -v -x ' + settings.HTTP_PROXY + '  -H "' + cheaders + '" ' + extattrsurl
    #logger.info(intcurl)
    links = []
    links.append(extattrsurl)
    links.append(extcurl)
    links.append(intattrsurl)
    links.append(intcurl)
    headers = {}
    headers["Authorization"] = "Bearer " + str(access_token)
    proxies = {}
    proxies["http"] = str(settings.HTTP_PROXY)
    proxies["https"] = str(settings.HTTP_PROXY)

    # using internal url since this demo is running in the DMZ
    #msg = "   trying extcurl_cmdl of " + str(extcurl_cmdl) 
    #logger.info(msg)
    #status, result = runcmdl(extcurl_cmdl, True)
    #msg = "   status, result: " + str(status) + ', ' + str(result)
    #logger.info(msg)
    #dit = requests.get(intattrsurl, proxies=proxies, headers=headers)
    #msg = "   data in transit: " + dit.text
    #logger.info(msg)

    data['dit'] = 'demo text!! ---  dit.text -- for now until I figure out what is blocking this....!'

    # not finishing due to DMZ issue -- but this should be a good start
    # dit -- data in transit is a payload within the json web token (jwt.io)
    #decode_key = connection.project.get_decode_key()
    #dar = Fernet(decode_key)
    #dit = bytes_in_string(attributes[0][1])
    #decrypteddata = dar.decrypt(dit).decode()
    #data['cleardata'] = decrypteddata 

    pp = pprint.PrettyPrinter()
    ppdata = pp.pformat(data)
    logouturl = None
    qs = AuthToken.objects.filter(token=access_token)
    token = None
    if qs.count() == int(1):
        token = qs[0]

    qs = Connection.objects.filter(token=token)
    if qs.count() == int(1):
        connection_state = qs[0].project.get_connection_state()
        logouturl = 'https://gsl.noaa.gov/ssop/logout/' + str(connection_state)

    response = render(request, 'demoapp.html', {'data': ppdata, 'links': links, 'src':src, 'template':template, 'logouturl': logouturl})
    headers = {}
    headers["Authorization"] = "Bearer " + str(access_token)
    response['ssopheaders'] = headers
    return response

def demoapp_authorization(request, access_token = None):
    data = {}
    msg = "   demoapp_authorization request -- request = " + str(request)
    logger.info(msg)
    data['request'] = request 

    access_token = None
    if 'access_token=' in str(request):
        (junk, access_token) = str(request).split('=')
        access_token = access_token.replace("'>", "")
    msg = "   demoapp landing -- access_token = " + str(access_token)
    logger.info(msg)

    try:
        msg = "   request.headers = " + str(request.headers)
    except KeyError:
        msg = "   NO request.headers found"
    logger.info(msg)

    data['request.headers'] = msg 
    logger.info(msg)

    randr = {}
    randr['roles'] = [('admin', False), ('readwrite', True), ('readonly', False)]
    randr['responsibilties'] = ['backups', 'audit', 'maintenance']
    #data['randr'] = randr 

    # the trailing '/' is MANDATORY
    landing_url = "/ssop/sites/demoapp_python/"
    requesturl = "https://gsl-webstage8.gsd.esrl.noaa.gov" + landing_url
    msg = "   requesturl: " + str(requesturl)
    logger.info(msg)


    headers = {}
    headers["Authorization"] = "Bearer " + str(access_token)
    data['Authorization'] = "Bearer " + str(access_token)
    #userattributes = requests.get(infourl, proxies=proxies, headers=headers)
    #msg = "   tokenresponse: " + tokenresponse.text
    #logger.info(msg)

    #data = str(data)
    #msg = "       data: " + str(data)
    #logger.info(msg)

    authurl = "https://gsl.noaa.gov" + landing_url
    msg = "   demoapp_authorization authurl: " + str(authurl)
    logger.info(msg)
    
    request.session["Authorization"] = data['Authorization']
    response = redirect(authurl)

    response['ssopheaders'] = headers

    msg = "   demoapp_authorization response: " + str(response)
    logger.info(msg)
    msg = "   response.headers: " + str(response.headers)
    logger.info(msg)

    #response['data'] = data

    msg = "   demoapp_authorization returning response: " + str(response)
    logger.info(msg)
    return response

def ldg_auth_error(request):
    data = "Oopps, something went wrong!"
    return render(request, 'demoapp.html', {'data': data})

def graphnodeByNameAndNodeType(name, nodetype):
    qs = GraphNode.objects.filter(name=name, nodetype=nodetype)
    if qs.count() == int(0):
        gn = GraphNode(name=name, nodetype=nodetype)
        gn.save()
    else:
        gn = qs[0]
    return gn

def minmaxs_from_pos(pos):
    xmin = float(1000.0)
    xmax = -1.0 * xmin
    ymin = xmin
    ymax = -1.0 * xmin
    for k in pos.keys():
        array = str(pos[k])
        xy = array.replace('[', '').strip()
        xy = xy.replace(']', '').strip()
        xy = xy.split()
        x = xy[0]
        x = x.replace("'", "", 10)
        x = float(x)
        y = xy[1]
        y = y.replace("'", "", 10)
        y = float(y)

        if x < xmin:
            xmin = x
        if x > xmax:
            xmax = x 
        if y < ymin:
            ymin = y
        if y > ymax:
            ymax = y

    return xmin, xmax, ymin, ymax

def key_from_nodemapping(elk, nodemapping):
    (bs, es) = str(elk).split(', ')    
    bs = bs.replace("('", "")
    bs = bs.replace("'", "")
    es = es.replace("')", "")
    es = es.replace("'", "")
    b = int(0)
    e = int(0)
    for k in nodemapping.keys():
        if bs in str(nodemapping[k]):
           b = b + int(k)
        if es in str(nodemapping[k]):
           e = e + int(k)
    return (b, e)

def get_suu(seen, k):
    suu = None
    try: 
        suu = seen[k]['uu']
    except KeyError:
        pass

    if suu is None:
        try: 
            suu = seen[k]['name']
        except KeyError:
            pass
    return suu

# https://networkx.org/documentation/stable/auto_examples/drawing/plot_chess_masters.html#sphx-glr-auto-examples-drawing-plot-chess-masters-py
def make_connections_by_project_img():

    debugprint = {}
    pp = pprint.PrettyPrinter()

    initialize_nodetypes()
    conn_by_project = {}
    conn_by_uu = {}
    allconnections = Connection.objects.all()
    numconnections = allconnections.count()
    debugprint['allconnections'] = str(allconnections) 

    all_connections_verbose = []
    for c in allconnections:
        tpl = (c.get_projectname(), c.get_uniqueusername())
        if str(tpl) not in str(all_connections_verbose):
            all_connections_verbose.append(tpl)
    debugprint['all_connections_verbose'] = str(all_connections_verbose) 
        

    all_uniqueusers = Uniqueuser.objects.all()
    numuniqueusers = all_uniqueusers.count()

    projectnodetype = NodeType.objects.filter(type='Project').first()
    uniqueusernodetype = NodeType.objects.filter(type='Uniqueuser').first()
    allconnectionsnodetype = NodeType.objects.filter(type='AllConnections').first()

    ntattrs = {}
    if len(projectnodetype.get_attrs()) > int(8):
        ale = ast.literal_eval(projectnodetype.get_attrs())
    else:
        ale = {}
    for k in ale.keys():
        ntattrs[k] = ale[k] 

    uuattrs = {}
    if len(uniqueusernodetype.get_attrs()) > int(8):
        ale = ast.literal_eval(uniqueusernodetype.get_attrs())
    else:
        ale = {}
    for k in ale.keys():
        uuattrs[k] = ale[k] 

    pntoptions = {}
    if len(projectnodetype.get_options()) > int(8):
        ale = ast.literal_eval(projectnodetype.get_options())
    else:
        ale = {}
    for k in ale.keys():
        pntoptions[k] = ale[k] 

    if len(uniqueusernodetype.get_options()) > int(8):
        ale = ast.literal_eval(uniqueusernodetype.get_options())
    else:
        ale = {}
    for k in ale.keys():
        debugprint[k] = ale[k] 

    for conn in allconnections:
        pname = conn.get_projectname()
        try:
            prev = conn_by_project[pname]['weight']
            conn_by_project[pname]['weight'] = prev + int(1) 
        except KeyError:
            conn_by_project[pname] = {}
            conn_by_project[pname]['weight'] = int(1)
            conn_by_project[pname]['uusers'] = {} 

        uuname = conn.get_uniqueusername()
        try:
            prev = conn_by_uu[uuname]['weight'] 
            conn_by_uu[uuname]['weight'] = prev + int(1) 
        except KeyError:
            conn_by_uu[uuname] = {}
            conn_by_uu[uuname]['weight'] = int(1)
            conn_by_uu[uuname]['projects'] = {} 

        try:
            prev = conn_by_project[pname]['uusers'][uuname]
            conn_by_project[pname]['uusers'][uuname] = prev + int(1) 
        except KeyError as ke:
            conn_by_project[pname]['uusers'][uuname] = int(1)

        try:
            prev = conn_by_uu[uuname]['projects'][pname]
            conn_by_uu[uuname]['projects'][pname] = prev + int(1) 
        except KeyError as ke:
            conn_by_uu[uuname]['projects'][pname] = int(1)

    ppout = pp.pformat(conn_by_project)
    debugprint['conn_by_project'] = str(ppout)
    debugprint['conn_by_project.keys'] = str(conn_by_project.keys())
    ppout = pp.pformat(conn_by_uu)
    debugprint['conn_by_uu'] = str(ppout)


    nodemapping_by_project = {}
    nodesizes_by_project = {}
    for pn in conn_by_project.keys():
        pname = str(pn)
        nodemapping_by_project[pname] = {}
        nodesizes_by_project[pname] = {}
    nodemapping_by_project['cbp'] = {}
    nodesizes_by_project['cbp'] = {}

    GraphNode.objects.all().delete()

    acstr = 'All Connections' 
    gn = graphnodeByNameAndNodeType(acstr, allconnectionsnodetype)
    all_connectionsnid = int(gn.nid())
    if settings.LABELNODES:
        nodemapping_by_project['cbp'][all_connectionsnid] = '[' + str(all_connectionsnid) + '] ' + acstr
    else:
        nodemapping_by_project['cbp'][all_connectionsnid] = acstr 
    nodemapping_by_project['cbp'][all_connectionsnid] += ' (' + str(numconnections) + ')' 
    nodesizes_by_project['cbp'][all_connectionsnid] = numconnections

    uulabel = 'All Unique Users' 
    gn = graphnodeByNameAndNodeType(uulabel, uniqueusernodetype)
    alluugnid = int(gn.nid())
    if settings.LABELNODES:
        nodemapping_by_project['cbp'][alluugnid] = '[' + str(alluugnid) + '] ' + uulabel + ' (' + str(numuniqueusers) + ')'
    else:
        nodemapping_by_project['cbp'][alluugnid] = uulabel + ' (' + str(numuniqueusers) + ')'
    nodesizes_by_project['cbp'][alluugnid] = numuniqueusers
    debugprint['all_uniqueusers'] = str(all_uniqueusers) 

    seen = {}
    seen_keys_by_project = {} 
    for pnk in conn_by_project.keys():
        pname = str(pnk)
        # this project to all connections
        gn = graphnodeByNameAndNodeType(pname, projectnodetype)
        pnnodenum = int(gn.nid())
        nodemapping_by_project[pname][pnnodenum] = pname
        nodemapping_by_project['cbp'][pnnodenum] = pname
        numconns = conn_by_project[pname]['weight']
        acstr = 'All Connections (' + str(numconns) + ')'
        if settings.LABELNODES:
            nodemapping_by_project[pname][all_connectionsnid] = '[' + str(all_connectionsnid) + '] ' + acstr
        else:
            nodemapping_by_project[pname][all_connectionsnid] = acstr

        numuus = len(conn_by_project[pname]['uusers'].keys())
        if settings.LABELNODES:
            nodemapping_by_project[pname][alluugnid] = '[' + str(alluugnid) + '] ' + uulabel + ' (' + str(numuus) + ')'
        else:
            nodemapping_by_project[pname][alluugnid] = uulabel + ' (' + str(numuus) + ')'

        try:
            prev = seen[(pnnodenum, all_connectionsnid)]['weight']
        except KeyError:
            prev = int(0) 
            attrs = {}
            attrs['name'] = pname
            attrs['type'] = 'P2AC' 
            attrs['pname'] = pname 
            seen[(pnnodenum, all_connectionsnid)] = attrs 
        seen[(pnnodenum, all_connectionsnid)]['weight'] = prev + int(1)

        try:
            test = seen_keys_by_project[pname]
        except KeyError:
            seen_keys_by_project[pname] = []
        seen_keys_by_project[pname].append((pnnodenum, all_connectionsnid))

        for k in conn_by_project[pname].keys():
            if str(k) == 'weight':
                continue
                
            # this project to each unique user
            for uu in conn_by_project[pname][k].keys():
                uugn = graphnodeByNameAndNodeType(str(uu), uniqueusernodetype)
                uugnid = int(uugn.nid())
                try:
                    prev = seen[(pnnodenum, uugnid)]['weight']
                except KeyError:
                    seen[(pnnodenum, uugnid)] = {} 
                    seen[(pnnodenum, uugnid)]['name'] = pname + ' -- ' + str(uu)
                    seen[(pnnodenum, uugnid)]['type'] = 'P2UU' 
                    seen[(pnnodenum, uugnid)]['pname'] = pname 
                    seen[(pnnodenum, uugnid)]['uu'] = str(uu) 
                    prev = int(0) 
                seen[(pnnodenum, uugnid)]['weight'] = prev + int(1)
                if str((pnnodenum, uugnid)) not in str(seen_keys_by_project[pname]):
                    seen_keys_by_project[pname].append((pnnodenum, uugnid))

    all_projalluugnids = set()
    for pn in conn_by_project.keys():
        pname = str(pn)
        proj_num_uu = len(conn_by_project[pname]['uusers'].keys())
        pgn = graphnodeByNameAndNodeType(pname, projectnodetype)
        pnnodenum = int(pgn.nid())
        for k in conn_by_project[pname].keys():
            if str(k) == 'weight':
                continue

            for uu in conn_by_project[pname][k].keys():
                uuname = str(uu)
                gn = graphnodeByNameAndNodeType(str(uu), uniqueusernodetype)
                unn = int(gn.nid())
                nodemapping_by_project[pname][unn] = uuname 
                nodemapping_by_project['cbp'][unn] = uuname
    
                # this uniqueuser to All uniqueusers and ALL projects; that is project 'cbp'
                try:
                    prev = seen[(unn, alluugnid)]['weight']
                except KeyError:
                    seen[(unn, alluugnid)] = {} 
                    seen[(unn, alluugnid)]['name'] = uuname 
                    seen[(unn, alluugnid)]['type'] = 'U2AU'
                    seen[(unn, alluugnid)]['pname'] = pname 
                    prev = int(0)
                seen[(unn, alluugnid)]['weight'] = prev + int(1)
                if str((unn, alluugnid)) not in str(seen_keys_by_project[pname]):
                    seen_keys_by_project[pname].append((unn, alluugnid))
    
                # this uniqueuser to this project
                try:
                    prev = seen[(pnnodenum, unn)]['weight']
                    seen[(pnnodenum, unn)]['weight'] = prev + int(1)
                except KeyError:
                    prev = int(0)
                    seen[(pnnodenum, unn)] = {} 
                    seen[(pnnodenum, unn)]['name'] = uuname 
                    seen[(pnnodenum, unn)]['type'] = 'U2P' 
                    seen[(pnnodenum, unn)]['pname'] = pname 
                seen[(pnnodenum, unn)]['weight'] = prev + int(1)
                if str((pnnodenum, unn)) not in str(seen_keys_by_project[pname]):
                    seen_keys_by_project[pname].append((pnnodenum, unn))
    
                # this user to all connections
                try:
                    prev = seen[(all_connectionsnid, unn)]['weight']
                except KeyError:
                    prev = int(0)
                    seen[(all_connectionsnid, unn)] = {} 
                    seen[(all_connectionsnid, unn)]['name'] = uuname 
                    seen[(all_connectionsnid, unn)]['type'] = 'U2AC' 
                    seen[(all_connectionsnid, unn)]['pname'] = pname
                seen[(all_connectionsnid, unn)]['weight'] = prev + int(1)
                if str((all_connectionsnid, unn)) not in str(seen_keys_by_project[pname]):
                    seen_keys_by_project[pname].append((all_connectionsnid, unn))

                # this uniqueuser to All uniqueusers for this project
                uulabel = str(pname) + ' Unique Users' 
                gn = graphnodeByNameAndNodeType(uulabel, uniqueusernodetype)
                projalluugnid = int(gn.nid())
                all_projalluugnids.add(projalluugnid)
                if settings.LABELNODES:
                    nodemapping_by_project[pname][projalluugnid] = '[' + str(projalluugnid) + '] ' + uulabel + ' (' + str(proj_num_uu) + ')'
                else:
                    nodemapping_by_project[pname][projalluugnid] = uulabel + ' (' + str(proj_num_uu) + ')'
                try:
                    prev = seen[(unn, projalluugnid)]['weight']
                except KeyError:
                    seen[(unn, projalluugnid)] = {} 
                    seen[(unn, projalluugnid)]['name'] = uuname 
                    seen[(unn, projalluugnid)]['type'] = 'U2AU'
                    seen[(unn, projalluugnid)]['pname'] = pname 
                    prev = int(0)
                seen[(unn, projalluugnid)]['weight'] = prev + int(1)
                if str((unn, projalluugnid)) not in str(seen_keys_by_project[pname]):
                    seen_keys_by_project[pname].append((unn, projalluugnid))


    debugprint['seen'] = pp.pformat(seen)
    debugprint['seen_keys_by_project'] = pp.pformat(seen_keys_by_project)

    total_by_uu_pn = {}
    for pn in conn_by_project.keys():
        pname = str(pn)
        gn = graphnodeByNameAndNodeType(pname, projectnodetype)
        pnn = int(gn.nid())
        if settings.LABELNODES:
            nodemapping_by_project[pname][pnn] = '[' + str(pnn) + '] ' + nodemapping_by_project[pname][pnn] + ' (' + str(conn_by_project[pname]['weight']) + ')'
        else:
            nodemapping_by_project[pname][pnn] = nodemapping_by_project[pname][pnn] + ' (' + str(conn_by_project[pname]['weight']) + ')'

        cbtweight = conn_by_project[pname]['weight']
        if settings.LABELNODES:
            nodemapping_by_project['cbp'][pnn] = '[' + str(pnn) + '] ' + nodemapping_by_project['cbp'][pnn] + ' (' + str(cbtweight) + ')'
        else:
            nodemapping_by_project['cbp'][pnn] = nodemapping_by_project['cbp'][pnn] + ' (' + str(cbtweight) + ')'

        nodesizes_by_project[pname][pnn] = cbtweight

        for k in conn_by_project[pname].keys():
            if str(k) == 'uusers':
                for uu in conn_by_project[pname][k].keys():
                    uuname = str(uu)
                    try:
                        prev = total_by_uu_pn[uuname]
                    except KeyError:
                        total_by_uu_pn[uuname] = {}

                    try:
                        prev = total_by_uu_pn[uuname][pname]
                        total_by_uu_pn[uuname][pname] += prev
                    except KeyError:
                        total_by_uu_pn[uuname][pname] = conn_by_project[pname][k][uuname] 
        debugprint['total_by_uu_pn'] = pp.pformat(total_by_uu_pn)

    for uu in total_by_uu_pn.keys():
        uuname = str(uu)
        gn = graphnodeByNameAndNodeType(uuname, uniqueusernodetype)
        unn = int(gn.nid())
        uutotal = int(0)
        for pn in total_by_uu_pn[uu].keys():
            pname = str(pn)
            pntotal = total_by_uu_pn[uuname][pname] 
            uutotal += total_by_uu_pn[uuname][pname] 
            if settings.LABELNODES:
                nodemapping_by_project[pname][unn] = '[' + str(unn) + '] ' + nodemapping_by_project[pname][unn] + ' (' + str(pntotal) + ')'
            else:
                nodemapping_by_project[pname][unn] = nodemapping_by_project[pname][unn] + ' (' + str(pntotal) + ')'
            try:
                test = nodesizes_by_project[pname][unn]
            except KeyError:
                nodesizes_by_project[pname][unn] = pntotal 
                nodesizes_by_project[pname][all_connectionsnid] = pntotal 
                nodesizes_by_project[pname][alluugnid] = pntotal 

        try:
            if settings.LABELNODES:
                nodemapping_by_project['cbp'][unn] = '[' + str(unn) + '] ' + nodemapping_by_project['cbp'][unn] + ' (' + str(uutotal) + ')'
            else:
                nodemapping_by_project['cbp'][unn] = nodemapping_by_project['cbp'][unn] + ' (' + str(uutotal) + ')'
        except KeyError:
            pass

        try:
            nodesizes_by_project['cbp'][unn] = uutotal
        except KeyError:
            pass
        nodesizes_by_project['cbp'][alluugnid] += uutotal


    # edge types
    # P2AC  -- project to all connection
    # P2UU  -- project to a unique user
    # U2AU  -- unique user to All unique users 
    # U2P   -- unique user to a project
    # U2AC  -- unique user to all connections

    edges_by_project = {}
    edges_by_uu = {}
    edges_by_uu['cbp'] = [] 
    edges_by_pac = {}
    # for each project
    for pnk in seen_keys_by_project.keys():
        pname = str(pnk)
        try:
            test = edges_by_project[pname]
        except KeyError:
            edges_by_project[pname] = []

        try:
            test = edges_by_uu[pname]
        except KeyError:
            edges_by_uu[pname] = []

        try:
            test = edges_by_pac[pname]
        except KeyError:
            edges_by_pac[pname] = []

        for k in seen_keys_by_project[pnk]:
            (b, e) = str(k).split(', ')
            b = int(b.replace('(', ''))
            e = int(e.replace(')', ''))
            a = seen[k]
            type = seen[k]['type']
            suu = get_suu(seen, k)

            if pname in seen[k]['pname']:
                if 'P2UU' in type:
                    a['weight'] = int(conn_by_uu[suu]['weight'])
    
                if 'U2P' in type:
                    try:
                        a['weight'] = int(conn_by_uu[suu]['projects'][pname])
                    except KeyError:
                        pass
    
                if 'U2AU' in type:
                        a['weight'] = int(conn_by_project[pname]['uusers'][suu])
                        edges_by_uu[pname].append((b, e, a))
    
                if 'U2AC' in type:
                    a['weight'] = int(conn_by_project[pname]['uusers'][suu])
    
                if 'P2AC' in type:
                    try:
                        a['weight'] = int(conn_by_uu[suu]['projects'][pname])
                    except KeyError:
                        pass
                    if str((b, e, a)) not in str(edges_by_pac):
                        edges_by_pac[pname].append((b, e, a))
    
                if pname in seen[k]['pname']:
                    edges_by_project[pname].append((b, e, a))

    # for the composite, 'connections by project' plot
    cbp_edges = []
    for k in seen.keys():
        (b, e) = str(k).split(', ')
        b = int(b.replace('(', ''))
        e = int(e.replace(')', ''))

        # do not add edges for the all connections by project
        found = False
        for pauu in all_projalluugnids:
            if int(pauu) == int(e):
                found = True
                continue
        if found:
           continue 

        a = seen[k]
        type = seen[k]['type']
        pname = seen[k]['pname']
        suu = get_suu(seen, k)

        if pname in seen[k]['pname']:
            if 'P2UU' in type:
                try:
                    a['weight'] = int(conn_by_uu[suu]['projects'][pname])
                except KeyError:
                    pass
    
            if 'U2P' in type:
                try:
                    a['weight'] = int(conn_by_uu[suu]['projects'][pname])
                except KeyError:
                    pass
    
            if 'U2AU' in type:
                try:
                    a['weight'] = int(seen[k]['weight'])
                except KeyError:
                    pass
    
            if 'U2AC' in type:
                try:
                    a['weight'] = int(conn_by_project[pname]['uusers'][suu])
                except KeyError:
                    pass
    
            if 'U2AU' in type:
                a['weight'] = int(seen[k]['weight'])
                edges_by_uu['cbp'].append((b, e, a))
    
            if 'P2AC' in type:
                try:
                    a['weight'] = int(conn_by_uu[suu]['projects'][pname])
                except KeyError:
                    pass
                if str((b, e, a)) not in str(edges_by_pac[pname]):
                    edges_by_pac[pname].append((b, e, a))

            a['type'] = type
            a['pname'] = pname
            a['uuname'] = suu 
            cbp_edges.append((b, e, a))

    debugprint['edges_by_project'] = pp.pformat(edges_by_project)
    debugprint['edges_by_uu'] = pp.pformat(edges_by_uu)
    debugprint['edges_by_pac'] = pp.pformat(edges_by_pac)
    debugprint['nodemapping_by_project'] = pp.pformat(nodemapping_by_project)

    allprojects = []
    allprojects.append('cbp')
    for pn in Project.objects.all():
        allprojects.append(str(pn))
    debugprint['allprojects'] = allprojects 

    edge_labels_by_project = {} 
    uuedge_labels_by_project = {} 
    pacedge_labels_by_project = {} 
    conndict_by_project = {}
    nodesizeslist_by_project = {}
    for pn in allprojects:
        pname = str(pn)
        uuedges = []
        try:
            for e in edges_by_uu[pname]:
                uuedges.append(e)
        except KeyError:
            pass

        pacedges = []
        try:
            for e in edges_by_pac[pname]:
                pacedges.append(e)
        except KeyError:
            pass

        edges = []
        if 'cbp' not in pname:
            try:
                for e in edges_by_project[pname]:
                    edges.append(e)
            except KeyError:
                pass
        else:
            try:
                for e in cbp_edges:
                    edges.append(e)
            except KeyError:
                pass

        try:
            nodemapping = nodemapping_by_project[pname]
        except KeyError:
            nodemapping = {}

        edge_labels_by_project[pname] = {} 
        uuedge_labels_by_project[pname] = {} 
        pacedge_labels_by_project[pname] = {} 
        gname = "Connections to " + str(pname)

        G = nx.Graph(name=gname)
        G.add_edges_from(edges)

        UUG = nx.Graph()
        UUG.add_edges_from(uuedges)
        uuedge_labels = nx.get_edge_attributes(UUG, "weight")
        np = int(1) 
        if 'cbp' in pname: 
            np = len(uuedge_labels.keys())
        for k in uuedge_labels.keys():
            #this_label = str(uuedge_labels[k]) + ' connection'
            this_label = str(uuedge_labels[k]) + ' C'
            if uuedge_labels[k] > int(1):
               this_label = this_label + 's'

            #this_label = this_label + ' to ' + str(np) + ' project'
            this_label = this_label + ' to ' + str(np) + ' P'
            if np > int(1):
               this_label = this_label + 's'

            uuedge_labels[k] = this_label

        uuedge_labels_by_project[pname] = {}
        for k in uuedge_labels.keys():
            uuedge_labels_by_project[pname][k] = uuedge_labels[k] 

        PACG = nx.Graph()
        PACG.add_edges_from(pacedges)
        pacedge_labels = nx.get_edge_attributes(PACG, "weight")
        for k in pacedge_labels.keys():
            this_label = pacedge_labels[k]
            if this_label > int(1):
               plural = True
            else:
               plural = False 
            this_label = str(this_label)
            if plural:
               this_label = this_label + 's'
            pacedge_labels[k] = this_label

        pacedge_labels_by_project[pname] = {}
        for k in pacedge_labels.keys():
            pacedge_labels_by_project[pname][k] = pacedge_labels[k] 

        H = nx.Graph(G)
        debugprint['Hedges'] = H.edges()

        I = nx.Graph(UUG)
        edges_from_uug = UUG.edges()
        debugprint['edges_from_uug'] = edges_from_uug
        debugprint['Iedges'] = I.edges()
    
        # edge width is proportional number of connections 
        #edgewidth = [len(G.get_edge_data(u, v)) for u, v in H.edges()]
        edgewidth = [int(G.get_edge_data(u, v)['weight']) for u, v in H.edges()]
        uuedgewidth = [int(UUG.get_edge_data(u, v)['weight']) for u, v in I.edges()]
        debugprint['uuedgewidth'] = uuedgewidth
        
        edgedata = {}
        for u, v in H.edges():
            edgedata[(u, v)] = H.get_edge_data(u, v)
    
        conndict = dict.fromkeys(G.nodes(), 1)

        try:
            test = conndict_by_project[pname]
        except KeyError:
            conndict_by_project[pname] = {}
        conndict_by_project[pname] = conndict 

        scale = int(1500)
        maxsize = scale * int(3)
        maxfound = int(0)
        nodesizeslist = []
        for k in conndict.keys():
            try:
                value = scale * nodesizes_by_project[pname][k]
            except KeyError:
                value = scale
            if value > maxsize:
                maxfound = value
                value = maxsize 
            nodesizeslist.append(value)
        try:
            test = nodesizeslist_by_project[pname]
        except KeyError:
            nodesizeslist_by_project[pname] = {}
        nodesizeslist_by_project[pname] = nodesizeslist 
    
        debugprint['conndict'] = conndict
        debugprint['nodesizeslist'] = nodesizeslist
    
        G = nx.relabel_nodes(G, nodemapping)
        edge_labels = nx.get_edge_attributes(G, "weight")
        for elk in edge_labels.keys():
            k = key_from_nodemapping(elk, nodemapping)
            (b, e) = str(k).split(', ')
            b = int(b.replace('(', ''))
            e = int(e.replace(')', ''))
            found = False 
            try:
                prev = uuedge_labels[k]
                found = True
            except KeyError:
                pass

            if not found:
                # reversed indicies
                try:
                    prev = uuedge_labels[(e, b)]
                    found = True 
                except KeyError:
                    pass

            if not found:
                try:
                    prev = pacedge_labels[k]
                    found = True
                except KeyError:
                    pass

            if not found:
                # reversed indicies
                try:
                    prev = pacedge_labels[(e, b)]
                    found = True
                except KeyError:
                    pass

            if not found:
                if edge_labels[elk] > int(1):
                   plural = True
                else:
                   plural = False 
                prev = str(edge_labels[elk]) + ' connection'
                if plural:
                    prev = prev + 's'
            edge_labels[elk] = prev

        for k in edge_labels.keys():
            edge_labels_by_project[pname][k] = edge_labels[k] 

        #G = nx.relabel_nodes(G, nodemapping)
        # https://networkx.org/documentation/stable/reference/drawing.html
        #pos = nx.spectral_layout(G)
        pos = nx.spring_layout(G, seed=10)

        (pxmin, pxmax, pymin, pymax) = minmaxs_from_pos(pos)
        debugprint['pxmin'] = pxmin 
        debugprint['pxmax'] = pxmax 
        debugprint['pymin'] = pymin 
        debugprint['pymax'] = pymax 

        updatedx = -1.0 * (pxmax + pxmin) / 2.0
        updatedy = pymin - (0.2 * (pymax - pymin) / 2.0)
    
        debugprint['pos'] = str(pos)
    
        updated = pname + ' -- ' + datetime.datetime.utcnow().strftime("Updated: %m/%d/%Y %H:%M:%S Z")
        plt.figure(figsize=(12,6.75))
        plt.clf()

        fig_width, fig_height = plt.gcf().get_size_inches()
        debugprint['fig_width'] = fig_width
        debugprint['fig_height'] = fig_height
        xmin, xmax = plt.xlim()
        debugprint['xmin'] = xmin 
        debugprint['xmax'] = xmax 
        ymin, ymax = plt.ylim()
        debugprint['ymin'] = ymin 
        debugprint['ymax'] = ymax 
        debugprint['updatedx'] = updatedx 
        debugprint['updatedy'] = updatedy 

        plt.text(updatedx, updatedy, updated)
        if len(nodesizeslist) > int(0):
            ret_nodes = nx.draw_networkx_nodes(G, pos, node_size=nodesizeslist)
            ret_edges = nx.draw_networkx_edges(G, pos, width=edgewidth, alpha=0.5)

            label_options = {"ec": "k", "fc": "white", "alpha": 0.71}
            ret_labels = nx.draw_networkx_labels(G, pos, font_size=10, bbox=label_options)
            #ret_elabels = nx.draw_networkx_edge_labels(G, pos)
            ret_elabels = nx.draw_networkx_edge_labels(G, pos, edge_labels)
            #plt.subplots_adjust(left=0.1, right=0.9, top=0.9, bottom=0.1)
    
        plt.tight_layout()
        src = '/usr/share/nginx/html/static/graphs/' + str(pname) + '.jpeg'
        plt.savefig(src)

    debugprint['conndict_by_project'] =  pp.pformat(conndict_by_project)
    debugprint['nodesizeslist_by_project'] =  pp.pformat(nodesizeslist_by_project)
    debugprint['nodesizes_by_project'] = pp.pformat(nodesizes_by_project)
    debugprint['edge_labels_by_project'] = pp.pformat(edge_labels_by_project)
    debugprint['uuedge_labels_by_project'] = pp.pformat(uuedge_labels_by_project)
    imageattributes = []
    lmr = Lmr()
    for p in Project.objects.all().order_by('display_order'):
        if p.is_enabled():
            logo = '/ssop/static/projects/' + str(p) + '/logo'
            link = 'https://gsl.noaa.gov/ssop/ldg/' + str(p)
            linktext = p.get_verbose_name()
            imageattributes.append((str(p), link, linktext, logo, lmr.next()))
    debugprint['imageattributes'] = imageattributes
    return (imageattributes, debugprint)

def connections_by_project(request):
    (imageattributes, debugprint) = make_connections_by_project_img()
    pp = pprint.PrettyPrinter()
    data = {}
    data['attributes'] = imageattributes
    data['debugprint'] = pp.pformat(debugprint)
    return render(request, 'conn_by_proj.html', data)

# commented out until end of file
##klh
##klh#from lib2to3.pgen2 import token
##klh#from django.http import HttpResponse
##klh#from django.views import generic
##klh#from django.shortcuts import render
##klh#from django.http import HttpResponseNotAllowed, HttpResponse, HttpResponseRedirect, HttpResponseServerError
##klh#from django.contrib.auth.models import User
##klh#from django.contrib.auth import authenticate, login, get_user_model
##klh#from django.contrib.admin import AdminSite
##klhfrom django.views.decorators.cache import never_cache
##klhfrom django.urls import reverse
##klhfrom django.utils.translation import gettext as _
##klh
##klhfrom django.views.decorators.csrf import ensure_csrf_cookie
##klhfrom django.contrib.auth import REDIRECT_FIELD_NAME
##klh#from ssop import settings
##klh#
##klh#import ast
##klh#import jwt
##klh#import requests
##klh#import random
##klh#import secrets
##klh#import json
##klh#import datetime
##klh#import re
##klh#import logging
##klh#import os
##klh
##klhSESSION_KEY = '_auth_user_id'
##klh
##klh
##klh@never_cache
##klhdef samlauth(request):
##klh    """
##klh    Display the login form for the given HttpRequest.
##klh    """
##klh    #msg = "in samlauth  -- request: " + str(request)
##klh    #logger.info(msg)
##klh
##klh    rmsg = '        in samlauth found ' + str(len(request.session.keys())) + ' session keys:\n'
##klh    #for k in request.session.keys():
##klh    #    msg = str(k)
##klh    #    #  + ": " + str(request.session[k])
##klh    #    rmsg = rmsg + msg + '\n'
##klh    logger.info(rmsg)
##klh    
##klh    # Already logged-in, redirect to admin index
##klh    index_path = "https://qrba-dev.gsd.esrl.noaa.gov/admin"
##klh    return HttpResponseRedirect(index_path)
##klh
##klh    # return HttpResponse("Hello, world. You're at qrba3 samlauth. " + str(rmsg))
##klh
##klhfrom onelogin.saml2.auth import OneLogin_Saml2_Auth, OneLogin_Saml2_Response
##klhfrom onelogin.saml2.settings import OneLogin_Saml2_Settings
##klhfrom onelogin.saml2.utils import OneLogin_Saml2_Utils, OneLogin_Saml2_Error, OneLogin_Saml2_ValidationError
##klhfrom onelogin.saml2.constants import OneLogin_Saml2_Constants
##klhfrom onelogin.saml2.utils import OneLogin_Saml2_Utils, OneLogin_Saml2_Error, OneLogin_Saml2_ValidationError, return_false_on_exception
##klhfrom onelogin.saml2.xml_utils import OneLogin_Saml2_XML
##klh
##klh
##klhclass noaaOneLogin_Saml2_Response(OneLogin_Saml2_Response):
##klh    def is_valid(self, request_data, request_id=None, raise_exceptions=False):
##klh        """
##klh        Validates the response object.
##klh
##klh        :param request_data: Request Data
##klh        :type request_data: dict
##klh
##klh        :param request_id: Optional argument. The ID of the AuthNRequest sent by this SP to the IdP
##klh        :type request_id: string
##klh
##klh        :param raise_exceptions: Whether to return false on failure or raise an exception
##klh        :type raise_exceptions: Boolean
##klh
##klh        :returns: True if the SAML Response is valid, False if not
##klh        :rtype: bool
##klh        """
##klh        self._error = None
##klh        try:
##klh            # Checks SAML version
##klh            if self.document.get('Version', None) != '2.0':
##klh                raise OneLogin_Saml2_ValidationError(
##klh                    'Unsupported SAML version',
##klh                    OneLogin_Saml2_ValidationError.UNSUPPORTED_SAML_VERSION
##klh                )
##klh
##klh            # Checks that ID exists
##klh            if self.document.get('ID', None) is None:
##klh                raise OneLogin_Saml2_ValidationError(
##klh                    'Missing ID attribute on SAML Response',
##klh                    OneLogin_Saml2_ValidationError.MISSING_ID
##klh                )
##klh
##klh            # Checks that the response has the SUCCESS status
##klh            self.check_status()
##klh
##klh            # Checks that the response only has one assertion
##klh            if not self.validate_num_assertions():
##klh                raise OneLogin_Saml2_ValidationError(
##klh                    'SAML Response must contain 1 assertion',
##klh                    OneLogin_Saml2_ValidationError.WRONG_NUMBER_OF_ASSERTIONS
##klh                )
##klh
##klh            idp_data = self._settings.get_idp_data()
##klh            idp_entity_id = idp_data['entityId']
##klh            sp_data = self._settings.get_sp_data()
##klh            sp_entity_id = sp_data['entityId']
##klh
##klh            signed_elements = self.process_signed_elements()
##klh
##klh            has_signed_response = '{%s}Response' % OneLogin_Saml2_Constants.NS_SAMLP in signed_elements
##klh            has_signed_assertion = '{%s}Assertion' % OneLogin_Saml2_Constants.NS_SAML in signed_elements
##klh
##klh            #msg = "reponse.py -- is_valid: has_signed_response = " + str(has_signed_response)
##klh            #logger.info(msg)
##klh            #msg = "reponse.py -- is_valid: has_signed_assertion = " + str(has_signed_assertion)
##klh            #logger.info(msg)
##klh             
##klh            if self._settings.is_strict():
##klh                no_valid_xml_msg = 'Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd'
##klh                res = OneLogin_Saml2_XML.validate_xml(self.document, 'saml-schema-protocol-2.0.xsd', self._settings.is_debug_active())
##klh                if isinstance(res, str):
##klh                    raise OneLogin_Saml2_ValidationError(
##klh                        no_valid_xml_msg,
##klh                        OneLogin_Saml2_ValidationError.INVALID_XML_FORMAT
##klh                    )
##klh
##klh                # If encrypted, check also the decrypted document
##klh                if self.encrypted:
##klh                    res = OneLogin_Saml2_XML.validate_xml(self.decrypted_document, 'saml-schema-protocol-2.0.xsd', self._settings.is_debug_active())
##klh                    if isinstance(res, str):
##klh                        raise OneLogin_Saml2_ValidationError(
##klh                            no_valid_xml_msg,
##klh                            OneLogin_Saml2_ValidationError.INVALID_XML_FORMAT
##klh                        )
##klh
##klh                security = self._settings.get_security_data()
##klh                current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
##klh
##klh                # Check if the InResponseTo of the Response matchs the ID of the AuthNRequest (requestId) if provided
##klh                in_response_to = self.get_in_response_to()
##klh                if in_response_to is not None and request_id is not None:
##klh                    if in_response_to != request_id:
##klh                        raise OneLogin_Saml2_ValidationError(
##klh                            'The InResponseTo of the Response: %s, does not match the ID of the AuthNRequest sent by the SP: %s' % (in_response_to, request_id),
##klh                            OneLogin_Saml2_ValidationError.WRONG_INRESPONSETO
##klh                        )
##klh
##klh                if not self.encrypted and security['wantAssertionsEncrypted']:
##klh                    raise OneLogin_Saml2_ValidationError(
##klh                        'The assertion of the Response is not encrypted and the SP require it',
##klh                        OneLogin_Saml2_ValidationError.NO_ENCRYPTED_ASSERTION
##klh                    )
##klh
##klh                if security['wantNameIdEncrypted']:
##klh                    encrypted_nameid_nodes = self._query_assertion('/saml:Subject/saml:EncryptedID/xenc:EncryptedData')
##klh                    if len(encrypted_nameid_nodes) != 1:
##klh                        raise OneLogin_Saml2_ValidationError(
##klh                            'The NameID of the Response is not encrypted and the SP require it',
##klh                            OneLogin_Saml2_ValidationError.NO_ENCRYPTED_NAMEID
##klh                        )
##klh
##klh                # Checks that a Conditions element exists
##klh                if not self.check_one_condition():
##klh                    raise OneLogin_Saml2_ValidationError(
##klh                        'The Assertion must include a Conditions element',
##klh                        OneLogin_Saml2_ValidationError.MISSING_CONDITIONS
##klh                    )
##klh
##klh                # Validates Assertion timestamps
##klh                self.validate_timestamps(raise_exceptions=True)
##klh
##klh                # Checks that an AuthnStatement element exists and is unique
##klh                if not self.check_one_authnstatement():
##klh                    raise OneLogin_Saml2_ValidationError(
##klh                        'The Assertion must include an AuthnStatement element',
##klh                        OneLogin_Saml2_ValidationError.WRONG_NUMBER_OF_AUTHSTATEMENTS
##klh                    )
##klh
##klh                # Checks that the response has all of the AuthnContexts that we provided in the request.
##klh                # Only check if failOnAuthnContextMismatch is true and requestedAuthnContext is set to a list.
##klh                requested_authn_contexts = security['requestedAuthnContext']
##klh                if security['failOnAuthnContextMismatch'] and requested_authn_contexts and requested_authn_contexts is not True:
##klh                    authn_contexts = self.get_authn_contexts()
##klh                    unmatched_contexts = set(authn_contexts).difference(requested_authn_contexts)
##klh                    if unmatched_contexts:
##klh                        raise OneLogin_Saml2_ValidationError(
##klh                            'The AuthnContext "%s" was not a requested context "%s"' % (', '.join(unmatched_contexts), ', '.join(requested_authn_contexts)),
##klh                            OneLogin_Saml2_ValidationError.AUTHN_CONTEXT_MISMATCH
##klh                        )
##klh
##klh                # Checks that there is at least one AttributeStatement if required
##klh                attribute_statement_nodes = self._query_assertion('/saml:AttributeStatement')
##klh                if security.get('wantAttributeStatement', True) and not attribute_statement_nodes:
##klh                    raise OneLogin_Saml2_ValidationError(
##klh                        'There is no AttributeStatement on the Response',
##klh                        OneLogin_Saml2_ValidationError.NO_ATTRIBUTESTATEMENT
##klh                    )
##klh
##klh                encrypted_attributes_nodes = self._query_assertion('/saml:AttributeStatement/saml:EncryptedAttribute')
##klh                if encrypted_attributes_nodes:
##klh                    raise OneLogin_Saml2_ValidationError(
##klh                        'There is an EncryptedAttribute in the Response and this SP not support them',
##klh                        OneLogin_Saml2_ValidationError.ENCRYPTED_ATTRIBUTES
##klh                    )
##klh
##klh                # Checks destination
##klh                destination = self.document.get('Destination', None)
##klh                if destination:
##klh                    if not OneLogin_Saml2_Utils.normalize_url(url=destination).startswith(OneLogin_Saml2_Utils.normalize_url(url=current_url)):
##klh                        # TODO: Review if following lines are required, since we can control the
##klh                        # request_data
##klh                        #  current_url_routed = OneLogin_Saml2_Utils.get_self_routed_url_no_query(request_data)
##klh                        #  if not destination.startswith(current_url_routed):
##klh                        raise OneLogin_Saml2_ValidationError(
##klh                            'The response was received at %s instead of %s' % (current_url, destination),
##klh                            OneLogin_Saml2_ValidationError.WRONG_DESTINATION
##klh                        )
##klh                elif destination == '':
##klh                    raise OneLogin_Saml2_ValidationError(
##klh                        'The response has an empty Destination value',
##klh                        OneLogin_Saml2_ValidationError.EMPTY_DESTINATION
##klh                    )
##klh                # Checks audience
##klh                valid_audiences = self.get_audiences()
##klh                if valid_audiences and sp_entity_id not in valid_audiences:
##klh                    raise OneLogin_Saml2_ValidationError(
##klh                        '%s is not a valid audience for this Response' % sp_entity_id,
##klh                        OneLogin_Saml2_ValidationError.WRONG_AUDIENCE
##klh                    )
##klh
##klh                # Checks the issuers
##klh                issuers = self.get_issuers()
##klh                for issuer in issuers:
##klh                    if issuer is None or issuer != idp_entity_id:
##klh                        raise OneLogin_Saml2_ValidationError(
##klh                            'Invalid issuer in the Assertion/Response (expected %(idpEntityId)s, got %(issuer)s)' %
##klh                            {
##klh                                'idpEntityId': idp_entity_id,
##klh                                'issuer': issuer
##klh                            },
##klh                            OneLogin_Saml2_ValidationError.WRONG_ISSUER
##klh                        )
##klh
##klh                # Checks the session Expiration
##klh                session_expiration = self.get_session_not_on_or_after()
##klh                if session_expiration and session_expiration <= OneLogin_Saml2_Utils.now():
##klh                    raise OneLogin_Saml2_ValidationError(
##klh                        'The attributes have expired, based on the SessionNotOnOrAfter of the AttributeStatement of this Response',
##klh                        OneLogin_Saml2_ValidationError.SESSION_EXPIRED
##klh                    )
##klh
##klh                # Checks the SubjectConfirmation, at least one SubjectConfirmation must be valid
##klh                any_subject_confirmation = False
##klh                subject_confirmation_nodes = self._query_assertion('/saml:Subject/saml:SubjectConfirmation')
##klh
##klh                for scn in subject_confirmation_nodes:
##klh                    method = scn.get('Method', None)
##klh                    if method and method != OneLogin_Saml2_Constants.CM_BEARER:
##klh                        continue
##klh                    sc_data = scn.find('saml:SubjectConfirmationData', namespaces=OneLogin_Saml2_Constants.NSMAP)
##klh                    if sc_data is None:
##klh                        continue
##klh                    else:
##klh                        irt = sc_data.get('InResponseTo', None)
##klh                        if in_response_to and irt and irt != in_response_to:
##klh                            continue
##klh                        recipient = sc_data.get('Recipient', None)
##klh                        if recipient and current_url not in recipient:
##klh                            continue
##klh                        nooa = sc_data.get('NotOnOrAfter', None)
##klh                        if nooa:
##klh                            parsed_nooa = OneLogin_Saml2_Utils.parse_SAML_to_time(nooa)
##klh                            if parsed_nooa <= OneLogin_Saml2_Utils.now():
##klh                                continue
##klh                        nb = sc_data.get('NotBefore', None)
##klh                        if nb:
##klh                            parsed_nb = OneLogin_Saml2_Utils.parse_SAML_to_time(nb)
##klh                            if parsed_nb > OneLogin_Saml2_Utils.now():
##klh                                continue
##klh
##klh                        if nooa:
##klh                            self.valid_scd_not_on_or_after = OneLogin_Saml2_Utils.parse_SAML_to_time(nooa)
##klh
##klh                        any_subject_confirmation = True
##klh                        break
##klh
##klh                if not any_subject_confirmation:
##klh                    raise OneLogin_Saml2_ValidationError(
##klh                        'A valid SubjectConfirmation was not found on this Response',
##klh                        OneLogin_Saml2_ValidationError.WRONG_SUBJECTCONFIRMATION
##klh                    )
##klh
##klh                if security['wantAssertionsSigned'] and not has_signed_assertion:
##klh                    raise OneLogin_Saml2_ValidationError(
##klh                        'The Assertion of the Response is not signed and the SP require it',
##klh                        OneLogin_Saml2_ValidationError.NO_SIGNED_ASSERTION
##klh                    )
##klh
##klh                if security['wantMessagesSigned'] and not has_signed_response:
##klh                    raise OneLogin_Saml2_ValidationError(
##klh                        'The Message of the Response is not signed and the SP require it',
##klh                        OneLogin_Saml2_ValidationError.NO_SIGNED_MESSAGE
##klh                    )
##klh
##klh            if not signed_elements or (not has_signed_response and not has_signed_assertion):
##klh                raise OneLogin_Saml2_ValidationError(
##klh                    'No Signature found. SAML Response rejected',
##klh                    OneLogin_Saml2_ValidationError.NO_SIGNATURE_FOUND
##klh                )
##klh            else:
##klh                cert = self._settings.get_idp_cert()
##klh                fingerprint = idp_data.get('certFingerprint', None)
##klh                if fingerprint:
##klh                    fingerprint = OneLogin_Saml2_Utils.format_finger_print(fingerprint)
##klh                fingerprintalg = idp_data.get('certFingerprintAlgorithm', None)
##klh
##klh                multicerts = None
##klh                if 'x509certMulti' in idp_data and 'signing' in idp_data['x509certMulti'] and idp_data['x509certMulti']['signing']:
##klh                    multicerts = idp_data['x509certMulti']['signing']
##klh
##klh                # If find a Signature on the Response, validates it checking the original response
##klh                if has_signed_response and not OneLogin_Saml2_Utils.validate_sign(self.document, cert, fingerprint, fingerprintalg, xpath=OneLogin_Saml2_Utils.RESPONSE_SIGNATURE_XPATH, multicerts=multicerts, raise_exceptions=False):
##klh                    #msg = "    has_signed_reponse document: " + str(self.document)
##klh                    #logger.info(msg)
##klh                    raise OneLogin_Saml2_ValidationError(
##klh                        'Signature validation failed. SAML Response rejected',
##klh                        OneLogin_Saml2_ValidationError.INVALID_SIGNATURE
##klh                    )
##klh
##klh                document_check_assertion = self.decrypted_document if self.encrypted else self.document
##klh                if has_signed_assertion and not OneLogin_Saml2_Utils.validate_sign(document_check_assertion, cert, fingerprint, fingerprintalg, xpath=OneLogin_Saml2_Utils.ASSERTION_SIGNATURE_XPATH, multicerts=multicerts, raise_exceptions=False):
##klh                    # some NOAA systems cannot handle 256 bit encryption!  --- per conversation with icam team
##klh                    # HOWEVER, 256 must be used to intiate the response....
##klh                    msg = "    has_signed_assertion is " + str(has_signed_assertion) + ", NOT raising error OneLogin_Saml2_ValidationError -- xml document:" + str(self.get_xml_document())
##klh                    msg = msg + "    accepting assertion signed with sha-128 -- per ICAM team this is needed to support some legacy NOAA systems"
##klh
##klh                                         
##klh                    #raise OneLogin_Saml2_ValidationError(
##klh                    #    'Signature validation failed. SAML Response rejected',
##klh                    #    OneLogin_Saml2_ValidationError.INVALID_SIGNATURE
##klh                    #)
##klh
##klh            return True
##klh        except Exception as err:
##klh            self._error = str(err)
##klh            debug = self._settings.is_debug_active()
##klh            if debug:
##klh                print(err)
##klh            if raise_exceptions:
##klh                raise
##klh            return False
##klh
##klh
##klhclass noaaOneLogin_Saml2_Auth(OneLogin_Saml2_Auth):
##klh    response_class = noaaOneLogin_Saml2_Response
##klh
##klh
##klh# views from python-saml-master/demo-django/demo
##klhdef prepare_django_request(request):
##klh    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
##klh    result = {
##klh        'https': 'on' if request.is_secure() else 'off',
##klh        'http_host': request.META['HTTP_HOST'],
##klh        'script_name': request.META['PATH_INFO'],
##klh        'server_port': request.META['SERVER_PORT'],
##klh        'get_data': request.GET.copy(),
##klh        'post_data': request.POST.copy(),
##klh        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
##klh        # 'lowercase_urlencoding': True,
##klh        'query_string': request.META['QUERY_STRING']
##klh    }
##klh    #msg = '  prepare_django_request result len = ' + str(len(result))
##klh    #logger.debug(msg)
##klh    return result
##klh
##klh
##klh@ensure_csrf_cookie
##klhdef index_icam(request):
##klh    msg = 'views.py index_icam -- request = ' + str(request)
##klh    logger.info(msg)
##klh
##klh    #if SESSION_KEY in request.session:
##klh    #    msg = "      request.session items:"
##klh    #    logger.info(msg)
##klh    #    try:
##klh    #        for k, v in request.session.items():
##klh    #            msg = "        " + str(k) + " = " + str(v)
##klh    #            logger.info(msg)
##klh    #    except KeyError:
##klh    #        pass
##klh    #else:
##klh    #    msg = "      NO SESSION_KEY in request.session"
##klh    #    logger.info(msg)
##klh
##klh    req = prepare_django_request(request)
##klh    #msg = 'index_icam -- prepare_django_request req = '
##klh    #for k in req.keys():
##klh    #    msg = msg + '\n' + str(k) + ': ' + str(req[k])
##klh    #logger.info(msg)
##klh
##klh    auth = noaaOneLogin_Saml2_Auth(req, custom_base_path=settings.SAML_FOLDER)
##klh    #msg = 'auth: ' + str(auth)
##klh    #logger.info(msg)
##klh
##klh    errors = []
##klh    error_reason = None
##klh    not_auth_warn = False
##klh    success_slo = False
##klh    attributes = False
##klh    paint_logout = False
##klh    if 'sso' in req['get_data']:
##klh        login = auth.login()
##klh        #msg = 'sso login HttpResponseRedirect( ' + str(login) + ' )'
##klh        #logger.info(msg)
##klh        return HttpResponseRedirect(login)
##klh
##klh        # If AuthNRequest ID need to be stored in order to later validate it, do instead
##klh        #sso_built_url = auth.login()
##klh        #msg = 'sso_built_url: ' + str(sso_built_url)
##klh        #logger.info(msg)
##klh        #request.session['AuthNRequestID'] = auth.get_last_request_id()
##klh        #msg = 'sso request.session[AuthNRequestID]: '+ str(request.session['AuthNRequestID']) 
##klh        #logger.info(msg)
##klh        #return HttpResponseRedirect(sso_built_url)
##klh    elif 'sso2' in req['get_data']:
##klh        return_to = OneLogin_Saml2_Utils.get_self_url(req) + reverse('attrs')
##klh        return HttpResponseRedirect(auth.login(return_to)) 
##klh    elif 'slo' in req['get_data']:
##klh        name_id = session_index_icam = name_id_format = name_id_nq = name_id_spnq = None
##klh        if 'samlNameId' in request.session:
##klh            name_id = request.session['samlNameId']
##klh        if 'samlSessionIndex' in request.session:
##klh            session_index = request.session['samlSessionIndex']
##klh        if 'samlNameIdFormat' in request.session:
##klh            name_id_format = request.session['samlNameIdFormat']
##klh        if 'samlNameIdNameQualifier' in request.session:
##klh            name_id_nq = request.session['samlNameIdNameQualifier']
##klh        if 'samlNameIdSPNameQualifier' in request.session:
##klh            name_id_spnq = request.session['samlNameIdSPNameQualifier']
##klh
##klh        request_id = None
##klh        if 'LogoutRequestID' in request.session:
##klh            request_id = request.session['LogoutRequestID']
##klh
##klh        #msg = "   in slo -- request_id = " + str(request_id)
##klh        #logger.info(msg)
##klh
##klh        url = auth.logout(name_id=name_id, session_index=session_index, nq=name_id_nq, name_id_format=name_id_format, spnq=name_id_spnq)
##klh        msg = '       slo HttpResponseRedirect( ' + str(url) + ' )'
##klh        logger.info(msg)
##klh        return HttpResponseRedirect(url)
##klh
##klh        # If LogoutRequest ID need to be stored in order to later validate it, do instead
##klh        #slo_built_url = auth.logout(name_id=name_id, session_index=session_index)
##klh        #msg = 'slo_built_url: ' + str(slo_built_url)
##klh        #logger.info(msg)
##klh        #request.session['LogoutRequestID'] = auth.get_last_request_id()
##klh        #msg = 'request.session[LogoutRequestID]: '+ str(request.session['LogoutRequestID']) 
##klh        #logger.info(msg)
##klh
##klh        #return HttpResponseRedirect(slo_built_url)
##klh    elif 'acs' in req['get_data']:
##klh        request_id = None
##klh        if 'AuthNRequestID' in request.session:
##klh            request_id = request.session['AuthNRequestID']
##klh
##klh        #msg = 'acs request_id = ' + str(request_id)
##klh        #logger.info(msg)
##klh
##klh        auth.process_response(request_id=request_id)
##klh        errors = auth.get_errors()
##klh        #msg = "auth.process_response errors = " + str(errors)
##klh        #logger.info(msg)
##klh
##klh        not_auth_warn = not auth.is_authenticated()
##klh        #msg = "    acs not_auth_warn = " + str(not_auth_warn)
##klh        #logger.info(msg)
##klh        #msg = "    acs auth.get_attributes() = " + str(auth.get_attributes())
##klh        #logger.info(msg)
##klh        #msg = "    acs auth.get_attribute('ou2') = " + str(auth.get_attribute('ou2'))
##klh        #logger.info(msg)
##klh        if not errors:
##klh            if 'AuthNRequestID' in request.session:
##klh                del request.session['AuthNRequestID']
##klh            request.session['samlUserdata'] = auth.get_attributes()
##klh            request.session['samlNameId'] = auth.get_nameid()
##klh            request.session['samlNameIdFormat'] = auth.get_nameid_format()
##klh            request.session['samlNameIdNameQualifier'] = auth.get_nameid_nq()
##klh            request.session['samlNameIdSPNameQualifier'] = auth.get_nameid_spnq()
##klh            request.session['samlSessionIndex'] = auth.get_session_index()
##klh            #msg = 'session items:'
##klh            #logger.info(msg)
##klh            #for k in request.session.keys():
##klh            #    msg = str(k) + ": " + str(request.session[k])
##klh            #    logger.info(msg)
##klh
##klh            if 'RelayState' in req['post_data'] and OneLogin_Saml2_Utils.get_self_url(req) != req['post_data']['RelayState']:
##klh                # To avoid 'Open Redirect' attacks, before execute the redirection confirm
##klh                # the value of the req['post_data']['RelayState'] is a trusted URL.
##klh                msg = '  acs HttpResponseRedirect( ' + str(auth.redirect_to(req['post_data']['RelayState'])) + ' )'
##klh                logger.info(msg)
##klh                return HttpResponseRedirect(auth.redirect_to(req['post_data']['RelayState']))
##klh        elif auth.get_settings().is_debug_active():
##klh                error_reason = auth.get_last_error_reason()
##klh    elif 'sls' in req['get_data']:
##klh        request_id = None
##klh        if 'LogoutRequestID' in request.session:
##klh            request_id = request.session['LogoutRequestID']
##klh
##klh        #msg = "   in sls -- request.session: " + str(request.session)
##klh        #for item in request.session:
##klh        #    msg = msg + "              " + str(item)
##klh        #logger.info(msg)
##klh
##klh        dscb = lambda: request.session.flush()
##klh        #msg = "    dscb = " + str(dscb)
##klh        #logger.info
##klh
##klh        url = auth.process_slo(request_id=request_id, delete_session_cb=dscb)
##klh
##klh        #msg = "      cleaned request_session:\n"
##klh        #for item in request.session:
##klh        #    msg = msg + "              " + str(item)
##klh        #logger.info(msg)
##klh
##klh        errors = auth.get_errors()
##klh        if len(errors) == 0:
##klh            #msg = "      slo url: " + str(url)
##klh            #logger.info(msg)
##klh            if url is not None:
##klh                # To avoid 'Open Redirect' attacks, before execute the redirection confirm
##klh                # the value of the url is a trusted URL.
##klh                msg = "   sls HttpResponseRedirect( " + str(url) + ' )'
##klh                logger.info(msg)
##klh                return HttpResponseRedirect(url)
##klh            else:
##klh                msg = "     -- sls render logged_out.html"
##klh                logger.info(msg)
##klh                return render(request, 'logged_out.html')
##klh
##klh        elif auth.get_settings().is_debug_active():
##klh            error_reason = auth.get_last_error_reason()
##klh
##klh    if 'samlUserdata' in request.session:
##klh        paint_logout = True
##klh        if len(request.session['samlUserdata']) > 0:
##klh            attributes = request.session['samlUserdata'].items()
##klh
##klh    if attributes:
##klh        #msg = "attributes: " + str(attributes)
##klh        #logger.info(msg)
##klh        email = None
##klh        sirname = None
##klh        givenname = None
##klh        for (k, v) in attributes:
##klh            if str(k) == 'mail':
##klh                email = v[0]
##klh            if str(k) == 'sn':
##klh                sirname = v[0]
##klh            if str(k) == 'givenName':
##klh                givenname = v[0]
##klh        #msg = "email: " + str(email)
##klh        #logger.info(msg)
##klh        username = givenname + '.' + sirname
##klh        #msg = '      username from SAML is ' + str(username)
##klh        #logger.info(msg)
##klh
##klh        user = None
##klh        qs = get_user_model().objects.filter(email=email)
##klh        if qs.count() > int(0):
##klh            user = qs[0]
##klh            #msg = msg + ", found backend User " + str(user)
##klh            #logger.info(msg)
##klh        else:
##klh            user = get_user_model().objects.create(email=email, username=username)
##klh            msg = "      created backend User " + str(user) + " for email = " + str(email) + " and username = " + str(username)
##klh            logger.info(msg)
##klh            
##klh        request.session['saml_auth_user'] = email
##klh
##klh        return_to = settings.AUTH_RETURN_TO
##klh        msg = "       attributes found -- HttpResponseRedirect( " + str(return_to) + ' )'
##klh        logger.info(msg)
##klh
##klh        return HttpResponseRedirect(return_to)
##klh    else:
##klh        msg = "     -- no attributes found render index.html"
##klh        logger.info(msg)
##klh        return render(request, 'index.html', {'errors': errors, 'error_reason': error_reason, not_auth_warn: not_auth_warn, 'success_slo': success_slo,
##klh                                            'attributes': attributes, 'paint_logout': paint_logout})
##klh
##klh@ensure_csrf_cookie
##klhdef attrs(request):
##klh    paint_logout = False
##klh    attributes = False
##klh
##klh    #msg = "in attrs, request: " + str(request)
##klh    #logger.info(msg)
##klh
##klh    #msg = "in attrs, request.session " + str(request.session)
##klh    #logger.info(msg)
##klh
##klh    if 'samlUserdata' in request.session:
##klh        paint_logout = True
##klh        if len(request.session['samlUserdata']) > 0:
##klh            attributes = request.session['samlUserdata'].items()
##klh
##klh    return render(request, 'attrs.html',
##klh                  {'paint_logout': paint_logout,
##klh                   'attributes': attributes})
##klh
##klh@ensure_csrf_cookie
##klhdef metadata(request):
##klh
##klh    #req = prepare_django_request(request)
##klh    #auth = init_saml_auth(req)
##klh    #saml_settings = auth.get_settings()
##klh    #msg = 'metadata request: ' + str(request)
##klh    #logger.info(msg)
##klh 
##klh    saml_settings = OneLogin_Saml2_Settings(settings=None, custom_base_path=settings.SAML_FOLDER, sp_validation_only=True)
##klh    metadata = saml_settings.get_sp_metadata().decode("utf-8")  
##klh    errors = saml_settings.validate_metadata(metadata)
##klh
##klh    if len(errors) == 0:
##klh        resp = HttpResponse(content=metadata, content_type='text/xml')
##klh    else:
##klh        resp = HttpResponseServerError(content=', '.join(errors))
##klh    return resp
##klh
##klh
##klh@ensure_csrf_cookie
##klhdef logged_out(request):
##klh    msg = "     in provision logged_out -- request: " + str(request)
##klh    logger.info(msg)
##klh    if request.session.user:
##klh        msg = "                logged out request.session user: " + str(request.session.user)
##klh    else:
##klh        msg = "                no request.session user"
##klh    logger.info(msg)
##klh
##klh    return render(request, 'logged_out.html')
##klh
##klh@ensure_csrf_cookie
##klhdef logout_saml(request):
##klh    msg = "     in logout_saml -- request: " + str(request)
##klh    logger.info(msg)
##klh
##klh    req = prepare_django_request(request)
##klh    auth = OneLogin_Saml2_Auth(req, custom_base_path=settings.SAML_FOLDER)
##klh
##klh    name_id = session_index = name_id_format = name_id_nq = name_id_spnq = None
##klh    if 'samlNameId' in request.session:
##klh        name_id = request.session['samlNameId']
##klh    if 'samlSessionIndex' in request.session:
##klh        session_index = request.session['samlSessionIndex']
##klh    if 'samlNameIdFormat' in request.session:
##klh        name_id_format = request.session['samlNameIdFormat']
##klh    if 'samlNameIdNameQualifier' in request.session:
##klh        name_id_nq = request.session['samlNameIdNameQualifier']
##klh    if 'samlNameIdSPNameQualifier' in request.session:
##klh        name_id_spnq = request.session['samlNameIdSPNameQualifier']
##klh
##klh    #Remove the authenticated user's ID from the request and flush their session data.
##klh    # Dispatch the signal before the user is logged out so the receivers have a
##klh    # chance to find out *who* logged out.
##klh    user = getattr(request, 'user', None)
##klh    if user is not None and 'anonymous' not in str(user).lower():
##klh        #user.is_active = False
##klh        user.is_staff = False
##klh        for g in user.groups.all():
##klh            user.groups.remove(g)
##klh        user.save()
##klh        user_logged_out.send(sender=user.__class__, request=request, user=user)
##klh
##klh    if SESSION_KEY in request.session:
##klh        request.session.flush()
##klh
##klh    request_id = None
##klh    if 'LogoutRequestID' in request.session:
##klh        request_id = request.session['LogoutRequestID']
##klh    #msg = "      request_id: " + str(request_id)
##klh    #logger.info(msg)
##klh
##klh    if hasattr(request, 'user'):
##klh        from django.contrib.auth.models import AnonymousUser
##klh        request.user = AnonymousUser()
##klh
##klh    #msg = "    auth.logout( " + str(name_id) + ", " + str(session_index) + ", " + str(name_id_nq) + ", " + str(name_id_format) + ", " + str(name_id_spnq) + " )"
##klh    #logger.info(msg)
##klh    url = auth.logout(name_id=name_id, session_index=session_index, nq=name_id_nq, name_id_format=name_id_format, spnq=name_id_spnq)
##klh    #msg = '    returning logout url = ' + str(url)
##klh    #logger.info(msg)
##klh    return HttpResponseRedirect(url)
##klh
##klh
##klh#--- end of views based on python-saml-master/demo-django/demo
##klh


def firewxoops(request):
    now = datetime.datetime.now()
    now = now.replace(tzinfo=pytz.UTC)
    html = "<html><body>Fire weather login.gov oops...  The time is now %s.</body></html>" % now
    return HttpResponse(html)
    
def firewxtb(request):

    src = 'unable to read sites/demoapp_python.txt'
    with open(os.path.join(settings.BASE_DIR, 'sites/demoapp_python.txt')) as srcfile:
        src = srcfile.read()

    template = 'unable to read templates/demoapp.html'
    with open(os.path.join(settings.BASE_DIR, 'templates/demoapp.html')) as srcfile:
        template = srcfile.read()

    data = {}
    msg = "   demoapp request -- request = " + str(request)
    logger.info(msg)
    data['request'] = request 

    access_token = None
    if 'access_token=' in str(request):
        (junk, access_token) = str(request).split('=')
        access_token = access_token[:-2]
    msg = "   demoapp landing -- access_token = " + str(access_token)
    logger.info(msg)

    try:
        msg = "   request.headers = " + str(request.headers)
    except KeyError:
        msg = "   NO request.headers found"
    data['request.headers'] = msg 
    #logger.info(msg)
    try:
        msg = request.session["Authorization"]
    except KeyError:
        msg = "   NO request.session found"
    data['request.session'] = msg 

    # the trailing '/' is MANDATORY
    extattrsurl = "https://gsl.noaa.gov/ssop/sites/attrsjwt/" + str(access_token) + "/"
    #msg = "   external attrsurl: " + str(extattrsurl)
    intattrsurl = "https://gsl-webstage8.gsd.esrl.noaa.gov/ssop/sites/attrsjwt/" + str(access_token) + "/"
    #msg = "   internal attrsurl: " + str(intattrsurl)
    #logger.info(msg)

    # curl headers need str vs {} for requests.get
    cheaders = '"Authorization: Bearer ' + str(access_token) + '"'

    extcurl_cmdl = []
    extcurl_cmdl.append('/usr/bin/curl')
    extcurl_cmdl.append('-v')
    extcurl_cmdl.append('-x')
    extcurl_cmdl.append(settings.HTTP_PROXY)
    extcurl_cmdl.append('-H')
    extcurl_cmdl.append(cheaders)
    extcurl_cmdl.append('https://noaa.gov')
    #extcurl_cmdl.append(intattrsurl)

    extcurl = 'curl -v -x ' + settings.HTTP_PROXY + '  -H "' + cheaders + '" ' + intattrsurl
    #logger.info(extcurl)
    intcurl = 'curl -v -x ' + settings.HTTP_PROXY + '  -H "' + cheaders + '" ' + extattrsurl
    #logger.info(intcurl)
    links = []
    links.append(extattrsurl)
    links.append(extcurl)
    links.append(intattrsurl)
    links.append(intcurl)
    headers = {}
    headers["Authorization"] = "Bearer " + str(access_token)
    proxies = {}
    proxies["http"] = str(settings.HTTP_PROXY)
    proxies["https"] = str(settings.HTTP_PROXY)

    # using internal url since this demo is running in the DMZ
    #msg = "   trying extcurl_cmdl of " + str(extcurl_cmdl) 
    #logger.info(msg)
    #status, result = runcmdl(extcurl_cmdl, True)
    #msg = "   status, result: " + str(status) + ', ' + str(result)
    #logger.info(msg)
    #dit = requests.get(intattrsurl, proxies=proxies, headers=headers)
    #msg = "   data in transit: " + dit.text
    #logger.info(msg)

    dittext = 'Welcome to Fire Weather Testbed\n\n'
    dittext = dittext + ' ---  dit demonstration text -- this will do for now until I figure out what is blocking this....!'
    data['dit'] = dittext

    # not finishing due to DMZ issue -- but this should be a good start
    # dit -- data in transit is a payload within the json web token (jwt.io)
    #decode_key = connection.project.get_decode_key()
    #dar = Fernet(decode_key)
    #dit = bytes_in_string(attributes[0][1])
    #decrypteddata = dar.decrypt(dit).decode()
    #data['cleardata'] = decrypteddata 

    pp = pprint.PrettyPrinter()
    ppdata = pp.pformat(data)
    logouturl = None
    qs = AuthToken.objects.filter(token=access_token)
    token = None
    if qs.count() == int(1):
        token = qs[0]

    qs = Connection.objects.filter(token=token)
    if qs.count() == int(1):
        connection_state = qs[0].project.get_connection_state()
        logouturl = 'https://gsl.noaa.gov/ssop/logout/' + str(connection_state)

    response = render(request, 'demoapp.html', {'data': ppdata, 'links': links, 'src':src, 'template':template, 'logouturl': logouturl})
    headers = {}
    headers["Authorization"] = "Bearer " + str(access_token)
    response['ssopheaders'] = headers
    return response

