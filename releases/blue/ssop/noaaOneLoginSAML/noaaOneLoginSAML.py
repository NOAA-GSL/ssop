from lib2to3.pgen2 import token
from django.http import HttpResponse
from django.views import generic
from django.shortcuts import render
from django.http import HttpResponseNotAllowed, HttpResponse, HttpResponseRedirect, HttpResponseServerError
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, get_user_model
from django.contrib.admin import AdminSite
from django.views.decorators.cache import never_cache
from django.urls import reverse
from django.utils.translation import gettext as _
from django.views.decorators.csrf import ensure_csrf_cookie
from django.contrib.auth import REDIRECT_FIELD_NAME
from ssop import settings

import ast
import jwt
import requests
import random
import secrets
import json
import datetime
import re
import logging
import os
from django.core.exceptions import ImproperlyConfigured

SESSION_KEY = '_auth_user_id'

logger = logging.getLogger('qrba.models')


@never_cache
def samlauth(request):
    """
    Display the login form for the given HttpRequest.
    """
    #msg = "in samlauth  -- request: " + str(request)
    #logger.info(msg)

    rmsg = '        in samlauth found ' + str(len(request.session.keys())) + ' session keys:\n'
    #for k in request.session.keys():
    #    msg = str(k)
    #    #  + ": " + str(request.session[k])
    #    rmsg = rmsg + msg + '\n'
    logger.info(rmsg)
    
    # Already logged-in, redirect to admin index
    index_path = "https://qrba-dev.gsd.esrl.noaa.gov/admin"
    return HttpResponseRedirect(index_path)

    # return HttpResponse("Hello, world. You're at qrba3 samlauth. " + str(rmsg))

from onelogin.saml2.auth import OneLogin_Saml2_Auth, OneLogin_Saml2_Response
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils, OneLogin_Saml2_Error, OneLogin_Saml2_ValidationError
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.utils import OneLogin_Saml2_Utils, OneLogin_Saml2_Error, OneLogin_Saml2_ValidationError, return_false_on_exception
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML


class noaaOneLogin_Saml2_Response(OneLogin_Saml2_Response):
    def is_valid(self, request_data, request_id=None, raise_exceptions=False):
        """
        Validates the response object.

        :param request_data: Request Data
        :type request_data: dict

        :param request_id: Optional argument. The ID of the AuthNRequest sent by this SP to the IdP
        :type request_id: string

        :param raise_exceptions: Whether to return false on failure or raise an exception
        :type raise_exceptions: Boolean

        :returns: True if the SAML Response is valid, False if not
        :rtype: bool
        """
        self._error = None
        try:
            # Checks SAML version
            if self.document.get('Version', None) != '2.0':
                raise OneLogin_Saml2_ValidationError(
                    'Unsupported SAML version',
                    OneLogin_Saml2_ValidationError.UNSUPPORTED_SAML_VERSION
                )

            # Checks that ID exists
            if self.document.get('ID', None) is None:
                raise OneLogin_Saml2_ValidationError(
                    'Missing ID attribute on SAML Response',
                    OneLogin_Saml2_ValidationError.MISSING_ID
                )

            # Checks that the response has the SUCCESS status
            self.check_status()

            # Checks that the response only has one assertion
            if not self.validate_num_assertions():
                raise OneLogin_Saml2_ValidationError(
                    'SAML Response must contain 1 assertion',
                    OneLogin_Saml2_ValidationError.WRONG_NUMBER_OF_ASSERTIONS
                )

            idp_data = self._settings.get_idp_data()
            idp_entity_id = idp_data['entityId']
            sp_data = self._settings.get_sp_data()
            sp_entity_id = sp_data['entityId']

            signed_elements = self.process_signed_elements()

            has_signed_response = '{%s}Response' % OneLogin_Saml2_Constants.NS_SAMLP in signed_elements
            has_signed_assertion = '{%s}Assertion' % OneLogin_Saml2_Constants.NS_SAML in signed_elements

            #msg = "reponse.py -- is_valid: has_signed_response = " + str(has_signed_response)
            #logger.info(msg)
            #msg = "reponse.py -- is_valid: has_signed_assertion = " + str(has_signed_assertion)
            #logger.info(msg)
             
            if self._settings.is_strict():
                no_valid_xml_msg = 'Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd'
                res = OneLogin_Saml2_XML.validate_xml(self.document, 'saml-schema-protocol-2.0.xsd', self._settings.is_debug_active())
                if isinstance(res, str):
                    raise OneLogin_Saml2_ValidationError(
                        no_valid_xml_msg,
                        OneLogin_Saml2_ValidationError.INVALID_XML_FORMAT
                    )

                # If encrypted, check also the decrypted document
                if self.encrypted:
                    res = OneLogin_Saml2_XML.validate_xml(self.decrypted_document, 'saml-schema-protocol-2.0.xsd', self._settings.is_debug_active())
                    if isinstance(res, str):
                        raise OneLogin_Saml2_ValidationError(
                            no_valid_xml_msg,
                            OneLogin_Saml2_ValidationError.INVALID_XML_FORMAT
                        )

                security = self._settings.get_security_data()
                current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)

                # Check if the InResponseTo of the Response matchs the ID of the AuthNRequest (requestId) if provided
                in_response_to = self.get_in_response_to()
                if in_response_to is not None and request_id is not None:
                    if in_response_to != request_id:
                        raise OneLogin_Saml2_ValidationError(
                            'The InResponseTo of the Response: %s, does not match the ID of the AuthNRequest sent by the SP: %s' % (in_response_to, request_id),
                            OneLogin_Saml2_ValidationError.WRONG_INRESPONSETO
                        )

                if not self.encrypted and security['wantAssertionsEncrypted']:
                    raise OneLogin_Saml2_ValidationError(
                        'The assertion of the Response is not encrypted and the SP require it',
                        OneLogin_Saml2_ValidationError.NO_ENCRYPTED_ASSERTION
                    )

                if security['wantNameIdEncrypted']:
                    encrypted_nameid_nodes = self._query_assertion('/saml:Subject/saml:EncryptedID/xenc:EncryptedData')
                    if len(encrypted_nameid_nodes) != 1:
                        raise OneLogin_Saml2_ValidationError(
                            'The NameID of the Response is not encrypted and the SP require it',
                            OneLogin_Saml2_ValidationError.NO_ENCRYPTED_NAMEID
                        )

                # Checks that a Conditions element exists
                if not self.check_one_condition():
                    raise OneLogin_Saml2_ValidationError(
                        'The Assertion must include a Conditions element',
                        OneLogin_Saml2_ValidationError.MISSING_CONDITIONS
                    )

                # Validates Assertion timestamps
                self.validate_timestamps(raise_exceptions=True)

                # Checks that an AuthnStatement element exists and is unique
                if not self.check_one_authnstatement():
                    raise OneLogin_Saml2_ValidationError(
                        'The Assertion must include an AuthnStatement element',
                        OneLogin_Saml2_ValidationError.WRONG_NUMBER_OF_AUTHSTATEMENTS
                    )

                # Checks that the response has all of the AuthnContexts that we provided in the request.
                # Only check if failOnAuthnContextMismatch is true and requestedAuthnContext is set to a list.
                requested_authn_contexts = security['requestedAuthnContext']
                if security['failOnAuthnContextMismatch'] and requested_authn_contexts and requested_authn_contexts is not True:
                    authn_contexts = self.get_authn_contexts()
                    unmatched_contexts = set(authn_contexts).difference(requested_authn_contexts)
                    if unmatched_contexts:
                        raise OneLogin_Saml2_ValidationError(
                            'The AuthnContext "%s" was not a requested context "%s"' % (', '.join(unmatched_contexts), ', '.join(requested_authn_contexts)),
                            OneLogin_Saml2_ValidationError.AUTHN_CONTEXT_MISMATCH
                        )

                # Checks that there is at least one AttributeStatement if required
                attribute_statement_nodes = self._query_assertion('/saml:AttributeStatement')
                if security.get('wantAttributeStatement', True) and not attribute_statement_nodes:
                    raise OneLogin_Saml2_ValidationError(
                        'There is no AttributeStatement on the Response',
                        OneLogin_Saml2_ValidationError.NO_ATTRIBUTESTATEMENT
                    )

                encrypted_attributes_nodes = self._query_assertion('/saml:AttributeStatement/saml:EncryptedAttribute')
                if encrypted_attributes_nodes:
                    raise OneLogin_Saml2_ValidationError(
                        'There is an EncryptedAttribute in the Response and this SP not support them',
                        OneLogin_Saml2_ValidationError.ENCRYPTED_ATTRIBUTES
                    )

                # Checks destination
                destination = self.document.get('Destination', None)
                if destination:
                    if not OneLogin_Saml2_Utils.normalize_url(url=destination).startswith(OneLogin_Saml2_Utils.normalize_url(url=current_url)):
                        # TODO: Review if following lines are required, since we can control the
                        # request_data
                        #  current_url_routed = OneLogin_Saml2_Utils.get_self_routed_url_no_query(request_data)
                        #  if not destination.startswith(current_url_routed):
                        raise OneLogin_Saml2_ValidationError(
                            'The response was received at %s instead of %s' % (current_url, destination),
                            OneLogin_Saml2_ValidationError.WRONG_DESTINATION
                        )
                elif destination == '':
                    raise OneLogin_Saml2_ValidationError(
                        'The response has an empty Destination value',
                        OneLogin_Saml2_ValidationError.EMPTY_DESTINATION
                    )
                # Checks audience
                valid_audiences = self.get_audiences()
                if valid_audiences and sp_entity_id not in valid_audiences:
                    raise OneLogin_Saml2_ValidationError(
                        '%s is not a valid audience for this Response' % sp_entity_id,
                        OneLogin_Saml2_ValidationError.WRONG_AUDIENCE
                    )

                # Checks the issuers
                issuers = self.get_issuers()
                for issuer in issuers:
                    if issuer is None or issuer != idp_entity_id:
                        raise OneLogin_Saml2_ValidationError(
                            'Invalid issuer in the Assertion/Response (expected %(idpEntityId)s, got %(issuer)s)' %
                            {
                                'idpEntityId': idp_entity_id,
                                'issuer': issuer
                            },
                            OneLogin_Saml2_ValidationError.WRONG_ISSUER
                        )

                # Checks the session Expiration
                session_expiration = self.get_session_not_on_or_after()
                if session_expiration and session_expiration <= OneLogin_Saml2_Utils.now():
                    raise OneLogin_Saml2_ValidationError(
                        'The attributes have expired, based on the SessionNotOnOrAfter of the AttributeStatement of this Response',
                        OneLogin_Saml2_ValidationError.SESSION_EXPIRED
                    )

                # Checks the SubjectConfirmation, at least one SubjectConfirmation must be valid
                any_subject_confirmation = False
                subject_confirmation_nodes = self._query_assertion('/saml:Subject/saml:SubjectConfirmation')

                for scn in subject_confirmation_nodes:
                    method = scn.get('Method', None)
                    if method and method != OneLogin_Saml2_Constants.CM_BEARER:
                        continue
                    sc_data = scn.find('saml:SubjectConfirmationData', namespaces=OneLogin_Saml2_Constants.NSMAP)
                    if sc_data is None:
                        continue
                    else:
                        irt = sc_data.get('InResponseTo', None)
                        if in_response_to and irt and irt != in_response_to:
                            continue
                        recipient = sc_data.get('Recipient', None)
                        if recipient and current_url not in recipient:
                            continue
                        nooa = sc_data.get('NotOnOrAfter', None)
                        if nooa:
                            parsed_nooa = OneLogin_Saml2_Utils.parse_SAML_to_time(nooa)
                            if parsed_nooa <= OneLogin_Saml2_Utils.now():
                                continue
                        nb = sc_data.get('NotBefore', None)
                        if nb:
                            parsed_nb = OneLogin_Saml2_Utils.parse_SAML_to_time(nb)
                            if parsed_nb > OneLogin_Saml2_Utils.now():
                                continue

                        if nooa:
                            self.valid_scd_not_on_or_after = OneLogin_Saml2_Utils.parse_SAML_to_time(nooa)

                        any_subject_confirmation = True
                        break

                if not any_subject_confirmation:
                    raise OneLogin_Saml2_ValidationError(
                        'A valid SubjectConfirmation was not found on this Response',
                        OneLogin_Saml2_ValidationError.WRONG_SUBJECTCONFIRMATION
                    )

                if security['wantAssertionsSigned'] and not has_signed_assertion:
                    raise OneLogin_Saml2_ValidationError(
                        'The Assertion of the Response is not signed and the SP require it',
                        OneLogin_Saml2_ValidationError.NO_SIGNED_ASSERTION
                    )

                if security['wantMessagesSigned'] and not has_signed_response:
                    raise OneLogin_Saml2_ValidationError(
                        'The Message of the Response is not signed and the SP require it',
                        OneLogin_Saml2_ValidationError.NO_SIGNED_MESSAGE
                    )

            if not signed_elements or (not has_signed_response and not has_signed_assertion):
                raise OneLogin_Saml2_ValidationError(
                    'No Signature found. SAML Response rejected',
                    OneLogin_Saml2_ValidationError.NO_SIGNATURE_FOUND
                )
            else:
                cert = self._settings.get_idp_cert()
                fingerprint = idp_data.get('certFingerprint', None)
                if fingerprint:
                    fingerprint = OneLogin_Saml2_Utils.format_finger_print(fingerprint)
                fingerprintalg = idp_data.get('certFingerprintAlgorithm', None)

                multicerts = None
                if 'x509certMulti' in idp_data and 'signing' in idp_data['x509certMulti'] and idp_data['x509certMulti']['signing']:
                    multicerts = idp_data['x509certMulti']['signing']

                # If find a Signature on the Response, validates it checking the original response
                if has_signed_response and not OneLogin_Saml2_Utils.validate_sign(self.document, cert, fingerprint, fingerprintalg, xpath=OneLogin_Saml2_Utils.RESPONSE_SIGNATURE_XPATH, multicerts=multicerts, raise_exceptions=False):
                    #msg = "    has_signed_reponse document: " + str(self.document)
                    #logger.info(msg)
                    raise OneLogin_Saml2_ValidationError(
                        'Signature validation failed. SAML Response rejected',
                        OneLogin_Saml2_ValidationError.INVALID_SIGNATURE
                    )

                document_check_assertion = self.decrypted_document if self.encrypted else self.document
                if has_signed_assertion and not OneLogin_Saml2_Utils.validate_sign(document_check_assertion, cert, fingerprint, fingerprintalg, xpath=OneLogin_Saml2_Utils.ASSERTION_SIGNATURE_XPATH, multicerts=multicerts, raise_exceptions=False):
                    # some NOAA systems cannot handle 256 bit encryption!  --- per conversation with icam team
                    # HOWEVER, 256 must be used to intiate the response....
                    msg = "    has_signed_assertion is " + str(has_signed_assertion) + ", NOT raising error OneLogin_Saml2_ValidationError -- xml document:" + str(self.get_xml_document())
                    msg = msg + "    accepting assertion signed with sha-128 -- per ICAM team this is needed to support some legacy NOAA systems"

                                         
                    #raise OneLogin_Saml2_ValidationError(
                    #    'Signature validation failed. SAML Response rejected',
                    #    OneLogin_Saml2_ValidationError.INVALID_SIGNATURE
                    #)

            return True
        except Exception as err:
            self._error = str(err)
            debug = self._settings.is_debug_active()
            if debug:
                print(err)
            if raise_exceptions:
                raise
            return False


class noaaOneLogin_Saml2_Auth(OneLogin_Saml2_Auth):
    response_class = noaaOneLogin_Saml2_Response


# views from python-saml-master/demo-django/demo
def prepare_django_request(request):
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
    #msg = '  prepare_django_request result len = ' + str(len(result))
    #logger.debug(msg)
    return result


@ensure_csrf_cookie
def index_icam(request):
    msg = 'views.py index_icam -- request = ' + str(request)
    logger.info(msg)

    #if SESSION_KEY in request.session:
    #    msg = "      request.session items:"
    #    logger.info(msg)
    #    try:
    #        for k, v in request.session.items():
    #            msg = "        " + str(k) + " = " + str(v)
    #            logger.info(msg)
    #    except KeyError:
    #        pass
    #else:
    #    msg = "      NO SESSION_KEY in request.session"
    #    logger.info(msg)

    req = prepare_django_request(request)
    #msg = 'index_icam -- prepare_django_request req = '
    #for k in req.keys():
    #    msg = msg + '\n' + str(k) + ': ' + str(req[k])
    #logger.info(msg)

    auth = noaaOneLogin_Saml2_Auth(req, custom_base_path=settings.SAML_FOLDER)
    #msg = 'auth: ' + str(auth)
    #logger.info(msg)

    errors = []
    error_reason = None
    not_auth_warn = False
    success_slo = False
    attributes = False
    paint_logout = False
    if 'sso' in req['get_data']:
        login = auth.login()
        #msg = 'sso login HttpResponseRedirect( ' + str(login) + ' )'
        #logger.info(msg)
        return HttpResponseRedirect(login)

        # If AuthNRequest ID need to be stored in order to later validate it, do instead
        #sso_built_url = auth.login()
        #msg = 'sso_built_url: ' + str(sso_built_url)
        #logger.info(msg)
        #request.session['AuthNRequestID'] = auth.get_last_request_id()
        #msg = 'sso request.session[AuthNRequestID]: '+ str(request.session['AuthNRequestID']) 
        #logger.info(msg)
        #return HttpResponseRedirect(sso_built_url)
    elif 'sso2' in req['get_data']:
        return_to = OneLogin_Saml2_Utils.get_self_url(req) + reverse('attrs')
        return HttpResponseRedirect(auth.login(return_to)) 
    elif 'slo' in req['get_data']:
        name_id = session_index_icam = name_id_format = name_id_nq = name_id_spnq = None
        if 'samlNameId' in request.session:
            name_id = request.session['samlNameId']
        if 'samlSessionIndex' in request.session:
            session_index = request.session['samlSessionIndex']
        if 'samlNameIdFormat' in request.session:
            name_id_format = request.session['samlNameIdFormat']
        if 'samlNameIdNameQualifier' in request.session:
            name_id_nq = request.session['samlNameIdNameQualifier']
        if 'samlNameIdSPNameQualifier' in request.session:
            name_id_spnq = request.session['samlNameIdSPNameQualifier']

        request_id = None
        if 'LogoutRequestID' in request.session:
            request_id = request.session['LogoutRequestID']

        #msg = "   in slo -- request_id = " + str(request_id)
        #logger.info(msg)

        url = auth.logout(name_id=name_id, session_index=session_index, nq=name_id_nq, name_id_format=name_id_format, spnq=name_id_spnq)
        msg = '       slo HttpResponseRedirect( ' + str(url) + ' )'
        logger.info(msg)
        return HttpResponseRedirect(url)

        # If LogoutRequest ID need to be stored in order to later validate it, do instead
        #slo_built_url = auth.logout(name_id=name_id, session_index=session_index)
        #msg = 'slo_built_url: ' + str(slo_built_url)
        #logger.info(msg)
        #request.session['LogoutRequestID'] = auth.get_last_request_id()
        #msg = 'request.session[LogoutRequestID]: '+ str(request.session['LogoutRequestID']) 
        #logger.info(msg)

        #return HttpResponseRedirect(slo_built_url)
    elif 'acs' in req['get_data']:
        request_id = None
        if 'AuthNRequestID' in request.session:
            request_id = request.session['AuthNRequestID']

        #msg = 'acs request_id = ' + str(request_id)
        #logger.info(msg)

        auth.process_response(request_id=request_id)
        errors = auth.get_errors()
        #msg = "auth.process_response errors = " + str(errors)
        #logger.info(msg)

        not_auth_warn = not auth.is_authenticated()
        #msg = "    acs not_auth_warn = " + str(not_auth_warn)
        #logger.info(msg)
        #msg = "    acs auth.get_attributes() = " + str(auth.get_attributes())
        #logger.info(msg)
        #msg = "    acs auth.get_attribute('ou2') = " + str(auth.get_attribute('ou2'))
        #logger.info(msg)
        if not errors:
            if 'AuthNRequestID' in request.session:
                del request.session['AuthNRequestID']
            request.session['samlUserdata'] = auth.get_attributes()
            request.session['samlNameId'] = auth.get_nameid()
            request.session['samlNameIdFormat'] = auth.get_nameid_format()
            request.session['samlNameIdNameQualifier'] = auth.get_nameid_nq()
            request.session['samlNameIdSPNameQualifier'] = auth.get_nameid_spnq()
            request.session['samlSessionIndex'] = auth.get_session_index()
            #msg = 'session items:'
            #logger.info(msg)
            #for k in request.session.keys():
            #    msg = str(k) + ": " + str(request.session[k])
            #    logger.info(msg)

            if 'RelayState' in req['post_data'] and OneLogin_Saml2_Utils.get_self_url(req) != req['post_data']['RelayState']:
                # To avoid 'Open Redirect' attacks, before execute the redirection confirm
                # the value of the req['post_data']['RelayState'] is a trusted URL.
                msg = '  acs HttpResponseRedirect( ' + str(auth.redirect_to(req['post_data']['RelayState'])) + ' )'
                logger.info(msg)
                return HttpResponseRedirect(auth.redirect_to(req['post_data']['RelayState']))
        elif auth.get_settings().is_debug_active():
                error_reason = auth.get_last_error_reason()
    elif 'sls' in req['get_data']:
        request_id = None
        if 'LogoutRequestID' in request.session:
            request_id = request.session['LogoutRequestID']

        #msg = "   in sls -- request.session: " + str(request.session)
        #for item in request.session:
        #    msg = msg + "              " + str(item)
        #logger.info(msg)

        dscb = lambda: request.session.flush()
        #msg = "    dscb = " + str(dscb)
        #logger.info

        url = auth.process_slo(request_id=request_id, delete_session_cb=dscb)

        #msg = "      cleaned request_session:\n"
        #for item in request.session:
        #    msg = msg + "              " + str(item)
        #logger.info(msg)

        errors = auth.get_errors()
        if len(errors) == 0:
            #msg = "      slo url: " + str(url)
            #logger.info(msg)
            if url is not None:
                # To avoid 'Open Redirect' attacks, before execute the redirection confirm
                # the value of the url is a trusted URL.
                msg = "   sls HttpResponseRedirect( " + str(url) + ' )'
                logger.info(msg)
                return HttpResponseRedirect(url)
            else:
                msg = "     -- sls render logged_out.html"
                logger.info(msg)
                return render(request, 'logged_out.html')

        elif auth.get_settings().is_debug_active():
            error_reason = auth.get_last_error_reason()

    if 'samlUserdata' in request.session:
        paint_logout = True
        if len(request.session['samlUserdata']) > 0:
            attributes = request.session['samlUserdata'].items()

    if attributes:
        #msg = "attributes: " + str(attributes)
        #logger.info(msg)
        email = None
        sirname = None
        givenname = None
        for (k, v) in attributes:
            if str(k) == 'mail':
                email = v[0]
            if str(k) == 'sn':
                sirname = v[0]
            if str(k) == 'givenName':
                givenname = v[0]
        #msg = "email: " + str(email)
        #logger.info(msg)
        username = givenname + '.' + sirname
        #msg = '      username from SAML is ' + str(username)
        #logger.info(msg)

        user = None
        qs = get_user_model().objects.filter(email=email)
        if qs.count() > int(0):
            user = qs[0]
            #msg = msg + ", found backend User " + str(user)
            #logger.info(msg)
        else:
            user = get_user_model().objects.create(email=email, username=username)
            msg = "      created backend User " + str(user) + " for email = " + str(email) + " and username = " + str(username)
            logger.info(msg)
            
        request.session['saml_auth_user'] = email

        return_to = settings.AUTH_RETURN_TO
        msg = "       attributes found -- HttpResponseRedirect( " + str(return_to) + ' )'
        logger.info(msg)

        return HttpResponseRedirect(return_to)
    else:
        msg = "     -- no attributes found render index.html"
        logger.info(msg)
        return render(request, 'index.html', {'errors': errors, 'error_reason': error_reason, not_auth_warn: not_auth_warn, 'success_slo': success_slo,
                                            'attributes': attributes, 'paint_logout': paint_logout})

@ensure_csrf_cookie
def attrs(request):
    paint_logout = False
    attributes = False

    #msg = "in attrs, request: " + str(request)
    #logger.info(msg)

    #msg = "in attrs, request.session " + str(request.session)
    #logger.info(msg)

    if 'samlUserdata' in request.session:
        paint_logout = True
        if len(request.session['samlUserdata']) > 0:
            attributes = request.session['samlUserdata'].items()

    return render(request, 'attrs.html',
                  {'paint_logout': paint_logout,
                   'attributes': attributes})

@ensure_csrf_cookie
def metadata(request):

    #req = prepare_django_request(request)
    #auth = init_saml_auth(req)
    #saml_settings = auth.get_settings()
    #msg = 'metadata request: ' + str(request)
    #logger.info(msg)
 
    saml_settings = OneLogin_Saml2_Settings(settings=None, custom_base_path=settings.SAML_FOLDER, sp_validation_only=True)
    metadata = saml_settings.get_sp_metadata().decode("utf-8")  
    errors = saml_settings.validate_metadata(metadata)

    if len(errors) == 0:
        resp = HttpResponse(content=metadata, content_type='text/xml')
    else:
        resp = HttpResponseServerError(content=', '.join(errors))
    return resp


@ensure_csrf_cookie
def logged_out(request):
    msg = "     in provision logged_out -- request: " + str(request)
    logger.info(msg)
    if request.session.user:
        msg = "                logged out request.session user: " + str(request.session.user)
    else:
        msg = "                no request.session user"
    logger.info(msg)

    return render(request, 'logged_out.html')

@ensure_csrf_cookie
def logout_saml(request):
    msg = "     in logout_saml -- request: " + str(request)
    logger.info(msg)

    req = prepare_django_request(request)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=settings.SAML_FOLDER)

    name_id = session_index = name_id_format = name_id_nq = name_id_spnq = None
    if 'samlNameId' in request.session:
        name_id = request.session['samlNameId']
    if 'samlSessionIndex' in request.session:
        session_index = request.session['samlSessionIndex']
    if 'samlNameIdFormat' in request.session:
        name_id_format = request.session['samlNameIdFormat']
    if 'samlNameIdNameQualifier' in request.session:
        name_id_nq = request.session['samlNameIdNameQualifier']
    if 'samlNameIdSPNameQualifier' in request.session:
        name_id_spnq = request.session['samlNameIdSPNameQualifier']

    #Remove the authenticated user's ID from the request and flush their session data.
    # Dispatch the signal before the user is logged out so the receivers have a
    # chance to find out *who* logged out.
    user = getattr(request, 'user', None)
    if user is not None and 'anonymous' not in str(user).lower():
        #user.is_active = False
        user.is_staff = False
        for g in user.groups.all():
            user.groups.remove(g)
        user.save()
        user_logged_out.send(sender=user.__class__, request=request, user=user)

    if SESSION_KEY in request.session:
        request.session.flush()

    request_id = None
    if 'LogoutRequestID' in request.session:
        request_id = request.session['LogoutRequestID']
    #msg = "      request_id: " + str(request_id)
    #logger.info(msg)

    if hasattr(request, 'user'):
        from django.contrib.auth.models import AnonymousUser
        request.user = AnonymousUser()

    #msg = "    auth.logout( " + str(name_id) + ", " + str(session_index) + ", " + str(name_id_nq) + ", " + str(name_id_format) + ", " + str(name_id_spnq) + " )"
    #logger.info(msg)
    url = auth.logout(name_id=name_id, session_index=session_index, nq=name_id_nq, name_id_format=name_id_format, spnq=name_id_spnq)
    #msg = '    returning logout url = ' + str(url)
    #logger.info(msg)
    return HttpResponseRedirect(url)


#--- end of views based on python-saml-master/demo-django/demo
