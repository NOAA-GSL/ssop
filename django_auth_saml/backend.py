"""
Authenticates against python3-saml 

"""
import ast
import copy
import datetime
from errno import EREMOTE
import operator
import pprint
import pytz
import re
from symbol import if_stmt
import warnings
from functools import reduce

import django.conf
import django.dispatch

from django.http import HttpResponseNotAllowed, HttpResponse, HttpResponseRedirect, HttpResponseServerError

from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured, ObjectDoesNotExist
from django.urls import reverse

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils
import random
import secrets

from ssop import settings

import logging
logger = logging.getLogger('ssop.models')

# Exported signals

# Allows clients to perform custom user population.
# Passed arguments: user, saml_user
populate_user = django.dispatch.Signal()

# Allows clients to inspect and perform special handling of SAMLError
# exceptions. Exceptions raised by handlers will be propagated out.
# Passed arguments: context, user, exception
saml_error = django.dispatch.Signal()

# Allows client to perform custom notifications to authenticated users
# Passed arguments: user, session
user_has_authenticated = django.dispatch.Signal()
user_login_failure = django.dispatch.Signal()

class SAMLBackend:
    """
    The main backend class. This implements the auth backend API, although it
    actually delegates most of its work to _SAMLUser, which is defined next.
    """

    _settings = None
    _saml = None  # The cached saml module (or mock object)

    # This is prepended to our internal setting names to produce the names we
    # expect in Django's settings file. Subclasses can change this in order to
    # support multiple collections of settings.
    settings_prefix = "AUTH_SAML_"

    # Default settings to override the built-in defaults.
    default_settings = {}

    def __getstate__(self):
        """
        Exclude certain cached properties from pickling.
        """
        return {
            k: v for k, v in self.__dict__.items() if k not in ["_settings", "_saml"]
        }

    @property
    def settings(self):
        if self._settings is None:
            self._settings = SAMLSettings(self.settings_prefix, self.default_settings)

        return self._settings

    @settings.setter
    def settings(self, settings):
        self._settings = settings

    @property
    def saml(self):
        if self._saml is None:
            options = getattr(django.conf.settings, "AUTH_SAML_GLOBAL_OPTIONS", None)
            self._saml = options

        return self._saml


    def get_user_model(self):
        """
        By default, this will return the model class configured by
        AUTH_USER_MODEL. Subclasses may wish to override it and return a proxy
        model.
        """
        um = get_user_model()
        return get_user_model()

    #
    # The Django auth backend API
    #

    def authenticate(self, request, **kwargs):

        saml_user = _SAMLUser(self, request=request)
        user = self.authenticate_saml_user(request, saml_user)
        #msg = '      user: ' + str(user) + ' for saml_user ' + str(saml_user)
        #logger.info(msg)
        if user is not None:
            user_has_authenticated.send(type(self), user=user, request=request)
        return user

    def get_user(self, user_id):
        user = None
        #msg = '   entering get_user, user_id = ' + str(user_id)
        #logger.info(msg)
        #msg = '                      self = ' + str(self)
        #logger.info(msg)
        #msg = '                      self.django_to_saml_username = ' + str(self.django_to_saml_username)
        #logger.info(msg)
        try:
            user = self.get_user_model().objects.get(pk=user_id)
            if not self.django_to_saml_username:
                _SAMLUser(self, user=user)  # This sets user.saml_user
        except ObjectDoesNotExist:
            pass
        #msg = '   leaving get_user, user = ' + str(user)
        #logger.info(msg)
        return user

    def has_perm(self, user, perm, obj=None):
        return perm in self.get_all_permissions(user, obj)

    def has_module_perms(self, user, app_label):
        for perm in self.get_all_permissions(user):
            if perm[: perm.index(".")] == app_label:
                return True

        return False

    def get_all_permissions(self, user, obj=None):
        return self.get_group_permissions(user, obj)

    def get_group_permissions(self, user, obj=None):
        if not hasattr(user, "saml_user") and self.settings.AUTHORIZE_ALL_USERS:
            _SAMLUser(self, user=user)  # This sets user.saml_user

        if hasattr(user, "saml_user"):
            permissions = user.saml_user.get_group_permissions()
        else:
            permissions = set()

        return permissions


    #
    # Hooks for subclasses
    #

    def authenticate_saml_user(self, request, saml_user, **kwargs):
        """
        Returns an authenticated Django user or None.
        """
        return saml_user.authenticate(request, **kwargs)

    def get_or_build_user(self, username, saml_user):
        """
        This must return a (User, built) 2-tuple for the given SAML user.

        username is the Django-friendly username of the user. saml_user.mail is
        the user's identifier and saml_user.attrs contains all of their isMemberOf
        attributes.

        The returned User object may be an unsaved model instance.

        """
        model = self.get_user_model()

        #msg = '     get_or_build_user -- ' + str(username)
        #logger.info(msg)
        
        if self.settings.USER_QUERY_FIELD:
            query_field = self.settings.USER_QUERY_FIELD
            query_value = saml_user.attrs[self.settings.USER_ATTR_MAP[query_field]][0]
            lookup = query_field
        else:
            query_field = model.USERNAME_FIELD
            query_value = username.lower()
            lookup = "{}__iexact".format(query_field)

        try:
            user = model.objects.get(**{lookup: query_value})
        except ObjectDoesNotExist:
            user = model(**{query_field: query_value})
            built = True
        else:
            built = False

        #msg = '       returning user: ' + str(user) + ', built = ' + str(built)
        #logger.info(msg)

        return (user, built)

    def saml_to_django_username(self, username):
        return username

    def django_to_saml_username(self, username):
        return username


class _SAMLUser:
    """
    Represents an SAML user and ultimately fields all requests that the
    backend receives.
    
    This class exists for two reasons. First, it's
    convenient to have a separate object for each request so that we can use
    object attributes without running into threading problems. Second, these
    objects get attached to the User objects, which allows us to cache
    expensive SAML information, especially around groups and permissions.

    self.backend is a reference back to the SAMLBackend instance, which we need
    to access the saml module and any hooks that a subclass has overridden.
    """

    class AuthenticationFailed(Exception):
        pass

    # Defaults
    _user = None
    _user_dn = None
    _user_attrs = None
    _group_names = set()
    _group_permissions = None

    #
    # Initialization
    #

    def __init__(self, backend, user=None, username=None, request=None):
        """
        A new SAMLUser must be initialized with either a username or an
        authenticated User object. If a user is given, the username will be
        ignored.
        """
        #msg = "     backend SAMLUser__init__: user = " + str(user) + ", username = " + str(username)
        #logger.info(msg)

        self.backend = backend
        self._username = None
        self._request = request
        self._attrs = None

        if request is not None:
            email = None
            attributes = None
            try:
                #for k in request.session.keys():
                #    msg = str(k) + ": " + str(request.session[k])
                #    logger.info(msg)
                email = str(request.session['samlNameId'])
                attributes = request.session['samlUserdata']
            except KeyError:
                pass
            #msg = '       in backend SAMLUser__init__ email is ' + str(email)
            #logger.info(msg)

            if email is not None:
                qs = self.backend.get_user_model().objects.filter(email=email)
                if qs.count() > int(0):
                    user = qs[0]
                    #msg = msg + ",found backend User " + str(user)
                    #logger.info(msg)
                else:
                    #msg = msg + "      creating user for email " + str(email)
                    #logger.info(msg)
                    username = str(email).split('@')[0]
                    uname = username.split('.')
                    firstname = uname[0]
                    lastname = uname[len(uname)-1]
                    user = self.backend.get_user_model().objects.create(email=email, username=username, first_name=firstname, last_name=lastname)
                    # password will be set later, after user has been saved
                    #msg = msg + ", created backend User " + str(user)
                    #logger.info(msg)
                    
            if user is not None:
                self._username = str(user)
                #msg = "    self._username " + str(self._username)
                #logger.info(msg)    
                self._attrs = attributes
                #msg = "    self._attrs " + str(self._attrs)
                #logger.info(msg)    
                self._set_authenticated_user(user)
                #msg = "       user " + str(user) + " SAML authenticated"
                #logger.info(msg)
                #user_has_authenticated.send(type(self), user=user, request=request)
            else:
                user_login_failure.send(type(self), user=user, request=request)

            if username is None and user is None:
                #raise ("Internal error: _SAMLUser improperly initialized.")
                msg = " _SAMLUser improperly initialized"
                logger.info(msg)
        else:
             msg = " request is " + str(request)
             logger.info(msg) 

    def __deepcopy__(self, memo):
        obj = object.__new__(type(self))
        obj.backend = self.backend
        obj._user = copy.deepcopy(self._user, memo)

        # This is all just cached immutable data. There's no point copying it.
        obj._username = self._username
        obj._user_dn = self._user_dn
        obj._attrs = self._attrs
        obj._user_attrs = self._user_attrs
        obj._group_permissions = self._group_permissions

        return obj

    def __getstate__(self):
        """
        Most of our properties are cached from the SAML server. We only want to
        pickle a few crucial things.
        """
        return {
            k: v
            for k, v in self.__dict__.items()
            if k in ["backend", "_username", "_user"]
        }

    def _set_authenticated_user(self, user):
        self._user = user
        self._username = self.backend.django_to_saml_username(user.get_username())

        user.saml_user = self
        user.saml_username = self._username

        #msg = "       _set_authenticated_user:   self._user = " + str(self._user) + ", self._username = " + str(self._username)
        #logger.info(msg)

    @property
    def saml(self):
        return self.backend.saml

    @property
    def settings(self):
        return self.backend.settings

    @property
    def group_names(self):
        return self.get_group_names()

    @property
    def dn(self):
        if self._user_dn is None:
            self._user_dn = self._username

        return self._user_dn

    @property
    def attrs(self):
        if self._user_attrs is None:
            self._load_user_attrs()

        return self._user_attrs

    #
    # Entry points
    #

    def authenticate(self, request):
        """
        Authenticates using SAML configuration and returns the corresponding
        User object if successful. Returns None on failure.
        """
        user = None
        #msg = "    in django_auth_saml authenticate request is " + str(request)
        #logger.debug(msg)
        try:
            self._authenticate_user_dn(request)
            self._check_requirements()
            self._get_or_create_user()

            user = self._user
        except self.AuthenticationFailed as e:
            #logger.debug("Authentication failed for {}: {}".format(self._username, e))
            results = saml_error.send(
                type(self.backend),
                context="authenticate",
                user=self._user,
                request=self._request,
                exception=e,
            )
            if len(results) == 0:
                logger.warning(
                    "Caught SAMLError while authenticating {}: {}".format(
                        self._username, pprint.pformat(e)
                    )
                )
        except Exception as e:
            logger.warning("{} while authenticating {}".format(e, self._username))
            raise

        #msg = "  leaving authenticate -- user is " + str(user)
        #logger.debug(msg)
        return user

    def get_group_permissions(self):
        """
        If allowed by the configuration, this returns the set of permissions
        defined by the user's group memberships via saml session.
        """
        if self._group_permissions is None:
            self._group_permissions = set()

            if self.settings.FIND_GROUP_PERMS:
                try:
                    if self.dn is not None:
                        self._load_group_permissions()
                except Exception as e:
                    results = saml_error.send(
                        type(self.backend),
                        context="get_group_permissions",
                        user=self._user,
                        request=self._request,
                        exception=e,
                    )
                    if len(results) == 0:
                        logger.warning(
                            "Caught SAMLIrror loading group permissions: {}".format(
                                pprint.pformat(e)
                            )
                        )

        return self._group_permissions

    """
    def populate_user(self):
        #---
        Populates the Django user object using the default bind credentials.
        #---
        user = None

        try:
            # self.attrs will only be non-None if we were able to load this user
            # from the SAML attributes, so this filters out nonexistent users.
            if self.attrs is not None:
                self._get_or_create_user(force_populate=True)

            user = self._user
        except Exception as e:
            logger.warning("{} while get_or_create_user {}".format(e, self._username))
            raise

        return user
    """

    #
    # Authentication
    #
    # views from python-saml-master/demo-django/demo
    def prepare_django_request(self, request):
        # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
        result = {
            'https': 'on' if request.is_secure() else 'off',
            'http_host': request.META['HTTP_HOST'],
            'script_name': request.META['PATH_INFO'],
            'server_port': request.META['SERVER_PORT'],
            'get_data': request.GET.copy(),
            'post_data': request.POST.copy(),
            # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
            # 'lowercase_urlencoding': True,
            'query_string': request.META['QUERY_STRING']
        }

        #if len(str(result['get_data'])) > int(0):
        #    msg = '  prepare_django_request get_data = ' + str(result['get_data'])
        #    logger.debug(msg)
        #if len(str(result['post_data'])) > int(0):
        #    msg = '       prepare_django_request post_data = ' + str(result['post_data'])
        #    logger.debug(msg)
        return result

    def _authenticate_user_dn(self, request):
        """
        Attempts SSO authentication. Raises
        AuthenticationFailed on failure.
        """
        attributes = False
        #msg = '  _authenticate_user_dn -- request = ' + str(request)
        #logger.info(msg)
        #if request.session:
        #    msg = "                request.session expiry age: " + str(request.session.get_expiry_age())
        #    logger.info(msg)

        req = self.prepare_django_request(request)
        #msg = ' _authenticate_user_dn -- prepare_django_request = ' + str(req)
        #logger.info(msg)

        auth = OneLogin_Saml2_Auth(req, custom_base_path=settings.SAML_FOLDER)
        #msg = 'auth: ' + str(auth)
        #logger.info(msg)

        errors = []
        #msg = 'index -- req = ' + str(req)
        #logger.info(msg)

        if 'sso' in req['get_data']:
            login = auth.login()
            #msg = '     _authuser HttpResponseRedirect( ' + str(login) + ' )'
            #logger.info(msg)
            return HttpResponseRedirect(login)
        elif 'acs' in req['get_data']:
            request_id = None
            if 'AuthNRequestID' in request.session:
                request_id = request.session['AuthNRequestID']

            #msg = "     a_u_dn acs request_id = " + str(request_id)
            #logger.info(msg)

            auth.process_response(request_id=request_id)
            errors = auth.get_errors()
            #msg = "     a_u_dn auth.process_response errors = " + str(errors)
            #logger.info(msg)

            not_auth_warn = not auth.is_authenticated()
            #msg = "     a_u_dn auth.is_authenticated() = " + str(auth.is_authenticated())
            #logger.info(msg)
            if not errors:
                #if 'AuthNRequestID' in request.session:
                #    del request.session['AuthNRequestID']
                request.session['samlUserdata'] = auth.get_attributes()
                request.session['samlNameId'] = auth.get_nameid()
                request.session['samlNameIdFormat'] = auth.get_nameid_format()
                request.session['samlNameIdNameQualifier'] = auth.get_nameid_nq()
                request.session['samlNameIdSPNameQualifier'] = auth.get_nameid_spnq()
                request.session['samlSessionIndex'] = auth.get_session_index()
                if 'RelayState' in req['post_data'] and OneLogin_Saml2_Utils.get_self_url(req) != req['post_data']['RelayState']:
                    # To avoid 'Open Redirect' attacks, before execute the redirection confirm
                    # the value of the req['post_data']['RelayState'] is a trusted URL.
                    #msg = '        _authuser HttpResponseRedirect( ' + str(auth.redirect_to(req['post_data']['RelayState'])) + ' )'
                    #logger.info(msg)
                    return HttpResponseRedirect(auth.redirect_to(req['post_data']['RelayState']))
            elif auth.get_settings().is_debug_active():
                    error_reason = auth.get_last_error_reason()
                    msg = '        ace error_reason: ' + str(error_reason)
                    logger.info(msg)

        if 'samlUserdata' in request.session:
            attributes = {}
            if len(request.session['samlUserdata']) > 0:
                for k, v in request.session['samlUserdata'].items():
                    attributes[k] = v

        #if attributes:
        #    msg = "backend found attribute keys " + str(attributes.keys())
        #    logger.debug(msg)
        #else:
        #    msg = "backend did not find attributes"
        #    logger.debug(msg)
        #    #raise self.AuthenticationFailed(
        #    #    "backend no attributes found"
        #    #)
    #
    # User management
    #

    def _get_or_create_user(self, force_populate=False):
        """
        Loads the User model object from the database or creates it if it
        doesn't exist. Also populates the fields, subject to
        AUTH_SAML_ALWAYS_UPDATE_USER.
        """
        save_user = False

        username = self.backend.saml_to_django_username(self._username)
        if username is None:
            return

        self._user, built = self.backend.get_or_build_user(username, self)
        self._user.saml_user = self
        self._user.saml_username = self._username

        should_populate = force_populate or self.settings.ALWAYS_UPDATE_USER or built
        #logger.info("  should_populate = {}".format(should_populate))
        self._user.set_unusable_password()
        if built:
            if self.settings.NO_NEW_USERS:
                raise self.AuthenticationFailed(
                    "user does not satisfy AUTH_SAML_NO_NEW_USERS"
                )

            logger.info("Creating Django user {}".format(username))
            self._user.set_unusable_password()
            save_user = True

        if should_populate:
            #logger.info("Populating Django user {}".format(username))
            self._populate_user()
            save_user = True

            # Give the client a chance to finish populating the user just
            # before saving.
            populate_user.send(type(self.backend), user=self._user, saml_user=self)

        if save_user:
            minlen = settings.LOCAL_PASSWORD_MINIMUM_LENGTH
            maxlen = 2 * minlen
            self._user.set_password(secrets.token_urlsafe(random.randint(minlen, maxlen)))
            self._user.save()

        # This has to wait until we're sure the user has a pk.
        if self.settings.MIRROR_GROUPS or self.settings.MIRROR_GROUPS_EXCEPT:
            #msg = "     self._group_names = " + str(self._group_names)
            #logger.info(msg)
            newgroups = set() 
            for (tag, usergroup) in self.settings.USER_FLAGS_BY_GROUP.items():
                #msg = "    (tag, group) = " + str(tag) + ", " + str(usergroup)
                #logger.info(msg)
                for sgn in self._group_names:
                    if settings.DEBUG_SAML_DEBUG:
                        if str('ssop') in str(sgn).lower():
                            msg = '     found ssop in ' + str(sgn).lower()
                            logger.info(msg)
                            pass 
                        if str('sysadm') in str(sgn).lower():
                            msg = '     found sysadm in ' + str(sgn).lower()
                            logger.info(msg)
                            pass
                    if str(usergroup).lower() in str(sgn).lower():
                        try:
                            ng = Group.objects.get(name=usergroup)
                            newgroups.add(ng)
                        except ObjectDoesNotExist:
                            pass
            #msg = "    newgroups are: " + str(newgroups)
            #logger.info(msg)
            save_user = False
            for ng in newgroups:
                #msg = "          adding " + str(ng) + " to self._user.groups"
                #logger.info(msg)
                self._user.groups.add(ng)
                save_user = True 
            if save_user:
                self._user.save()

    def _populate_user(self):
        """
        Populates our User object with information from the SAML attributes.
        """
        self._populate_user_from_attributes()
        # group membership has been handled in from_attributes
        #self._populate_user_from_group_memberships()

    def _populate_user_from_attributes(self):
        #msg = 'in _populate_user_from_attributes... '
        #logger.info(msg)
        attrs = self._attrs
        #msg = '  ----   attrs[mail]: ' + str(attrs['mail'])
        #logger.info(msg)
        date_joined = str(self._user.date_joined).split('+')[0]
        #msg = '  ----   ' + str(attrs['mail']) + ' joined on ' + date_joined
        #logger.info(msg)
        if '.' in str(date_joined):
            dj = datetime.datetime.strptime(date_joined, "%Y-%m-%d %H:%M:%S.%f")
        else:
            dj = datetime.datetime.strptime(date_joined, "%Y-%m-%d %H:%M:%S")
        dj = dj.replace(tzinfo=pytz.UTC)
        #msg = " now dj = " + str(dj)
        #logger.debug(msg)
        utcnow = datetime.datetime.utcnow()
        utcnow = utcnow.replace(tzinfo=pytz.UTC)
        #msg = " utcnow = " + str(utcnow)
        #logger.info(msg)
        account_age = utcnow - dj
        account_age_seconds = account_age.seconds + (86400 * account_age.days)
        #msg = " account_age = " + str(account_age) + ' == ' + str(account_age_seconds) + ' seconds' 
        #logger.info(msg)

        # user model to saml attributes lookup
        for ukey, akey in self.settings.USER_ATTR_MAP.items():
            #msg = '      ukey, akey = ' + str(ukey) + ", " + str(akey)
            #logger.info(msg)

            try:
                #msg = '      attrs[akey] = ' + str(attrs[akey])
                #logger.info(msg)
                if len(attrs[akey]) == 1:
                    # all attributes except ismemberof are scalars
                    value = attrs[akey][0]
                else:
                    # ismemberof is a list of groups
                    value = attrs[akey]
            except (TypeError, LookupError):
                # TypeError occurs when self.attrs is None as we were unable to
                # load this user's attributes.
                logger.warning(
                    "{} does not have a value for the attribute {}".format(
                        self.dn, akey
                    )
                )
                value = 'lookuperror'
            else:
                setattr(self._user, ukey, value)
                #msg = "     setattr( " + str(self._user) + ', ' + str(ukey) + ", " + str(value) + ' )'
                #logger.info(msg)

            # if this is the membership list, need to set user flags
            try:
                #msg = "  attrs[ " + str(akey) + " ] = " + str(attrs[akey])
                #msg = "  len(attrs[ " + str(akey) + " ]) = " + str(len(attrs[akey]))
                #logger.info(msg)
                groups_to_add = set() 
                for eachattr in attrs[akey]:
                    ag = str(eachattr)
                    #msg = "    USER_FLAGS_BY_GROUP attribute group = " + str(ag).lower()
                    #logger.info(msg)

                    # ismemberof is a list of groups
                    for flag, usergroup in self.settings.USER_FLAGS_BY_GROUP.items():
                        #msg = "     flag, group: " + str(flag) + ", " + str(group).lower() + '  for ag = ' + str(ag)
                        #logger.info(msg)
                        if str(ag).lower() in str(usergroup).lower():
                            if settings.DEBUG_SAML_DEBUG:
                                if str('ssop') in str(ag).lower() or str('ssop') in str(usergroup).lower():
                                    msg = '     found ssop in ' + str(ag).lower() + " or " + str(usergroup).lower()
                                    logger.info(msg)
                                if str('sysadm') in str(ag).lower() or str('sysadm') in str(usergroup).lower():
                                    msg = '     found sysadm in ' + str(ag).lower() + " or " + str(usergroup).lower()
                                    logger.info(msg)
                            #msg = '    ' + str(flag) + ' -- ag = ' + str(ag) + " is in user group " + str(usergroup).lower()
                            #logger.info(msg)
                            setflag = True
                            if str(flag) == 'is_active':
                                current_is_active = getattr(self._user, 'is_active')
                                #msg = "    current_is_active = " + str(current_is_active)
                                #logger.info(msg)
                                if current_is_active is False:
                                    # catch-22, we want to honor the is_active flag ... but it will be false when a user is initially created. 
                                    if int(account_age_seconds) > int(account_age_seconds):
                                        setflag = False
                                        #msg = "    account_age > MINIMUM_ACCOUNT_AGE " + str(int(account_age_seconds)) + " > " + str(int(account_age_seconds))
                                        #logger.info(msg)
                            if setflag:
                                setattr(self._user, flag, True)
                                #msg = '     ----------  ' + str(flag) + ' = ' + str(getattr(self._user, flag)) + '     , added ' + str(usergroup) + ' to group_names'
                                #logger.info(msg)
                                groups_to_add.add(usergroup)

                #msg = "    groups_to_add = " + str(groups_to_add)
                #logger.info(msg)
                for ug in groups_to_add:
                    #msg = "           ug = " + str(ug)
                    #logger.info(msg)
                    self._group_names.add(ug)
 

            except (TypeError, LookupError):
                # TypeError occurs when self._attrs is None as we were unable to
                # load this user's attributes.
                logger.warning(
                    "{} error setting {}".format(
                        self.dn, akey
                    )
                )


    def _check_requirements(self):
        """
        Checks all authentication requirements beyond credentials. Raises
        AuthenticationFailed on failure.
        """
        self._check_required_group()

    def _check_required_group(self):
        """
        Returns True if the group requirement met
        """

        try:
            email = str(self._request.session['samlNameId'])
        except KeyError:
            email = None
        #msg = " in check_required_group email is " + str(email)
        #logger.info(msg)

        if email is not None:
            result = True
            if not result:
                raise self.AuthenticationFailed(
                    "user does not satisfy AUTH_SAML_REQUIRE_GROUP"
                )

        return True

    def _load_user_attrs(self):
        #msg = " _load_user_attrs attributes: " + str(self._attrs)
        #logger.info(msg)
        if self.dn is not None:
            self._user_attrs = self._attrs

    def get_group_names(self):
        """
        Returns the set of Django group names that this user belongs to by
        virtue of SAML group memberships.
        """
        if self.group_names is None:
            self._load_cached_attr("_group_names")

        if self.group_names is None:
            group_infos = self._get_group_infos()
            self.group_names = {
                self._group_type.group_name_from_info(group_info)
                for group_info in group_infos
            }
            self._cache_attr("_group_names")

        return self.group_names

    def _get_group_infos(self):
        """
        Returns a (cached) list of group_info structures for the groups that our
        user is a member of.
        """
        if self._group_infos is None:
            self._group_infos = self._group_type.user_groups(
                self._saml_user, self._group_search
            )

        return self._group_infos



class SAMLSettings:
    """
    This is a simple class to take the place of the global settings object. An
    instance will contain all of our settings as attributes, with default values
    if they are not specified by the configuration.
    """

    _prefix = "AUTH_SAML_"

    defaults = {
        "ALWAYS_UPDATE_USER": True,
        "AUTHORIZE_ALL_USERS": False,
        "DENY_GROUP": None,
        "FIND_GROUP_PERMS": False,
        "MIRROR_GROUPS": True,
        "MIRROR_GROUPS_EXCEPT": None,
        "USER_ATTRLIST": None,
        "USER_ATTR_MAP": {},
        "USER_DN_TEMPLATE": None,
        "USER_QUERY_FIELD": None,
        "USER_FLAGS_BY_GROUP": {},
    }

    def __init__(self, prefix="AUTH_SAML_", defaults={}):
        """
        Loads our settings from django.conf.settings, applying defaults for any
        that are omitted.
        """
        self._prefix = prefix

        defaults = dict(self.defaults, **defaults)

        for name, default in defaults.items():
            value = getattr(django.conf.settings, prefix + name, default)
            setattr(self, name, value)

        def _name(self, suffix):
            return self._prefix + suffix

