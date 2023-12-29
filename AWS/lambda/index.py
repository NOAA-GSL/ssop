"""
Single Sign-On Portal (SSOP) Amazon Web Services (AWS) Integration

Implements the handler required to processes and access_token from gsl.noaa.gov/ssop or its sandbox version gsl.noaa.gov/ssopsb 

Its design allows an SSOP Project the ability to specify a method to be executed upon succesful authentication.

Project methods currently implemented:
   appstream2(params) -- creates and AppStream2 streaming URL based on input params

"""

import ast
import sys
import pprint
import random
import secrets

from botocore.exceptions import ClientError
import boto3
appstream = boto3.client('appstream')

# packages in layer ssop-imports
sys.path.append("/opt")
import requests
import jwt
from cryptography.fernet import Fernet, InvalidToken

ssm_client = boto3.client('ssm')


def userexists(email):
    result = False
    userinfo = appstream.describe_users(AuthenticationType='USERPOOL')
    for user in userinfo['Users']:
            if email in user['UserName']:
                result = True
                break
    return result
            
def checkusers(params):
    email = None
    try:
        email = params['email']
    except KeyError:
        pass
    try:
        first_name = params['given_name']
    except KeyError:
        pass
    try:
        family_name = params['family_name']
    except KeyError:
        pass
    
    userinfo = appstream.describe_users(AuthenticationType='USERPOOL')
    if email:
        for user in userinfo['Users']:
            try:
                if str(email) in str(user['email']):
                    if 'first_name' in user['FirstName'] or first_name not in user['FirstName'] or family_name not in user['LastName']:
                        print(" deleting user with first_name: " + str(user['FirstName']) + " and last name: " + str(user['LastName']))
                        appstream.delete_user(UserName=user['UserName'], AuthenticationType='USERPOOL')
            except KeyError:
                pass

    
def createAppStreamUser(params):
    email = 'email'
    first_name = 'first_name'
    family_name = 'family_name'
    try:
        email = params['email']
    except KeyError:
        pass

    if not userexists(email):
        try:
            first_name = params['given_name']
        except KeyError:
            pass
        try:
            family_name = params['family_name']
        except KeyError:
            pass

        try:
            appstream.create_user(UserName=email,
            MessageAction='SUPPRESS',
            FirstName=first_name,
            LastName=family_name,
            AuthenticationType='USERPOOL')
        except ClientError as e:
            pass
            print("ClientError e: " + str(e))
        except ResourceAlreadyExistsException:
            pass
            print("User exists error for: " + str(email))
        except Exception as e:
            pass
            print("Exception e: " + str(e))

    #except ClientError.InvalidAccountStatusException as e:
    #            print("e: " + str(e))
    #except ClientError.InvalidParameterCombinationException as e:
    #    print("e: " + str(e))
    #except ClientError.LimitExceededException as e:
    #    print("e: " + str(e))
    #except ClientError.OperationNotPermittedException as e:
    #    print("e: " + str(e)

    
def createas2streamingurl(params):
    email = 'email'

    try:
        email = params['email']
    except KeyError:
        pass
    
    try:
        awsRequestId = params['awsRequestId']
    except KeyError:
        awsRequestId = None
        
    try:
        FleetName = params['FleetName']
    except KeyError:
        pass
    
    try:
        StackName = params['StackName']
    except KeyError:
        pass
    
    try:
        Validity = int(params['Validity'])
    except KeyError:
        pass 
        
    try:
        UserStackAssociations = []
        userinfo = {}
        userinfo["StackName"] = StackName
        userinfo["UserName"] = email
        userinfo["AuthenticationType"] = "USERPOOL"
        userinfo["SendEmailNotification"] =  False
        UserStackAssociations.append(userinfo)
        associate_response = appstream.batch_associate_user_stack(UserStackAssociations=UserStackAssociations)
        #print("associate_response: " + str(associate_response))
        #print("UserStackAssociations: " + str(UserStackAssociations))
        request = appstream.create_streaming_url(FleetName=FleetName,
        StackName=StackName, UserId=email, Validity=Validity, ApplicationId='Desktop', SessionContext=email)
        url = request['StreamingURL']
        c2sresponse = {
                    'statusCode': 201,
                    'body': {
                        'Message': url,
                        'Reference': awsRequestId
                    },
                    'headers': {
                        'Access-Control-Allow-Origin': 'https://d2jdmiq7araut3.cloudfront.net'
                    }
                }
    except Exception as e:
        print(" Exception e: " + str(e))
    
    return c2sresponse

def appstream2(params):
    """
    SSOP Project method
    """
    checkusers(params)
    createAppStreamUser(params)
    return createas2streamingurl(params)

def bytes_in_string(b):
        if str(b).startswith("b'"):
            return str(b)[2:-1]
        else:
            return b

def handler(event, context):
    """
    processes access_token from gsl.noaa.gov/ssop[sb] 
    
    """

    try:
        qsp = event['queryStringParameters']
    except KeyError:
        qsp = None
    
    access_token = None
    if qsp:
        try:
            access_token = qsp['access_token']
        except KeyError:
            access_token = 'keyerror'
        
    output = "access_token = " + str(access_token)

    
    """
    user has been authenticated by login.gov, so we can retrive their attributes via a JWT
    """
    
    # fetch the decode ID
    proxies = {}
    didurl = 'https://gsl.noaa.gov/ssop/getdid/' + str(access_token) + '/'
    response = requests.get(didurl, proxies=proxies)
    FERNET_KEY_ID = response.text

    # Fall back and check sandbox environment if no key id
    if len(FERNET_KEY_ID) < int(10):
        didurl = 'https://gsl.noaa.gov/ssopsb/getdid/' + str(access_token) + '/'
        response = requests.get(didurl, proxies=proxies)
        FERNET_KEY_ID = response.text
        
    # our primary return structure -- useful for debugging
    data = {}
    #print("event: " + str(event))
    #print("context: " + str(context))
    #data['event'] = str(event)
    #data['context'] = str(context)
    if access_token is None:
        if '?access_token=' in str(event):
            (junk, access_token) = str(event).split('?access_token=')
            access_token = access_token.replace("\'>", "")
    data['access_token'] = str(access_token)
    try:
        msg = "   event.headers = " + str(event['headers'])
    except KeyError:
        msg = "   NO event.headers found"
    #data['event.headers'] = msg

    awsRequestId = None
    for e in str(context).split(','):
        try:
            if 'aws_request_id' in str(e):
                awsRequestId = str(e).split('=')
                awsRequestId = awsRequestId[1]
        except KeyError:
            pass
    data['event.context.aws_request_id'] = awsRequestId

    # the trailing '/' is MANDATORY
    extattrsurl = "https://gsl.noaa.gov/ssop/sites/attrsjwt/" + str(access_token) + "/"
    #print("extattrsurl: " + str(extattrsurl))
    
    # curl headers need str vs {} for requests.get
    cheaders = "Authorization: Bearer " + str(access_token)
    extcurl = 'curl -v -x -H "' + cheaders + '" ' + extattrsurl
    #data['extcurl'] = str(extcurl)

    headers = {}
    headers["Authorization"] = "Bearer " + str(access_token)

    jwtresponse = requests.get(extattrsurl, proxies=proxies, headers=headers)
    # Fall back to sandbox environment if no JWT returned
    if 'JWT' not in str(jwtresponse.text):
        extattrsurl = "https://gsl.noaa.gov/ssopsb/sites/attrsjwt/" + str(access_token) + "/"
        jwtresponse = requests.get(extattrsurl, proxies=proxies, headers=headers)
    data['jwt'] = str(jwtresponse.text)    
    #print("jwt: " + str(data['jwt']))
    data['extattrsurl'] = str(extattrsurl)

    payload = jwtresponse.text
    payload = payload.replace('\n', '', 10)
    payload = payload.replace('JWT ', '' )
    payload = payload.replace(' ', '' )
    data['payload'] = payload

    decoded = None
    try:
        # we trust the JWT since we know where it originated
        decoded = jwt.decode(payload, options={"verify_signature": False})
    except jwt.DecodeError as e:
        decoded = 'unable to decode from ' + str(extattrsurl) + ' ... e = ' + str(e)
    #data['decoded'] = str(decoded)
    #print("decoded: " + str(decoded))

    given_name = None
    family_name = None
    email = None
    full_name = None
    app_method = None
    FleetName = None
    StackName = None
    Validity = None
    decode_key = None
    return_html = None
    strmurl = None
    if decoded:
        dar = None
        try:
            get_param_response = ssm_client.get_parameter(Name=FERNET_KEY_ID)
        except Exception as e:
            print("Exception " + str(e) + " fetching parameter " + str(FERNET_KEY_ID))
            
        try:
            decode_key = get_param_response['Parameter']['Value']
            #print("decode_key: " + str(decode_key))
            dar = Fernet(decode_key)
            #print("dar: " + str(dar))
        except Exception as e:
            print("Exception " + str(e) + " fetching get_param_response " + str(get_param_response))

        # This will be all of user attributes in clear text
        # dit -- data in transit is a payload within the json web token (jwt.io)
        bis = None
        try:
            bis = bytes_in_string(decoded['dit'])
        except Exception as e:
            bis = str(e)
            #data['bis'] = bis
        #print("bis: " + str(bis))
        try:
            decodeddar = dar.decrypt(bis).decode()
            #print("decodeddar: " + str(decodeddar))
            ale = ast.literal_eval(decodeddar)
        except InvalidToken:
            ale = {}
            ale["InvalidToken"] = "True"
            ale = (ale,)
        #data['cleardata'] = str(ale)
        #print("ale: " + str(ale))

        # Application parameters
        #   we could also pass ale to globals()[app_method] instead of dealing with appstream2 specific parameters here, but this works         
        app_params = {}
        for tpl in ale:
            #print("tpl: " + str(tpl))
            if not given_name:
                try:
                    given_name = tpl['given_name']
                except KeyError:
                    pass
            if not family_name:
                try:
                    family_name = tpl['family_name']
                except KeyError:
                    pass
            if not email:
                try:
                    email = tpl['email']
                except KeyError:
                    pass
            if not app_method:
                try:
                    app_method = tpl['app_method']
                except KeyError:
                    pass
            if not FleetName:
                try:
                    FleetName = tpl['FleetName']
                    app_params['FleetName'] = FleetName
                except KeyError:
                    pass
            if not StackName:
                try:
                    StackName = tpl['StackName']
                    app_params['StackName'] = StackName
                except KeyError:
                    pass
            if not Validity:
                try:
                    Validity = tpl['Validity']
                    app_params['Validity'] = Validity
                except KeyError:
                    pass
            if not return_html:
                try:
                    return_html = tpl['return_html']
                    app_params['return_html'] = return_html
                except KeyError:
                    pass
                
        full_name = str(given_name) + '_' + str(family_name) + ' (' + str(email) + ')'
        if email:
            data['full_name'] = full_name
            params = {"given_name": given_name,
                      "family_name": family_name,
                      "email": email,
                      "awsRequestId": awsRequestId,
            }
            for p in app_params.keys():
                params[p] = app_params[p]
            #data['params'] = params
        
        #print("app_method: " + str(app_method))
        #print("full_name: " + str(full_name))
        if app_method:    
            strmurlresponse = globals()[app_method](params)
            data['strmurlresponse'] = strmurlresponse
            data['strmurl'] = strmurlresponse['body']['Message']
            #return strmurlresponse


    try:
        return_url = data['strmurl']
        JSON_RESPONSE = False
    except KeyError:
        JSON_RESPONSE = True
        return_url = 'unknown-return_url'

    try:
        strmrespheaders = data['strmurlresponse']['headers']
        strmrespbody = data['strmurlresponse']['body']
    except KeyError:
        strmrespheaders = {}
        strmrespbody = ""

    output = "return_url: " + str(return_url) + "\n" + output
    output = output + "\nFERNET_KEY_ID: " + str(FERNET_KEY_ID)
    #output = output + "\ndecode_key: " + str(decode_key)
    data['output'] = output


    # JSON response requires double quotes
    if JSON_RESPONSE:
        #data = str(data).replace('"', '#####', 10000)
        #data = data.replace("'", '"', 10000)
        #data = data.replace('##A###', '"', 10000)
        response = {
            "statusCode": 201,
            "body": output,
        }
        # "body": data
    else:
        safeurls = "https://gsl.noaa.gov https://a--------z.execute-api.region.amazonaws.com https://appstream2.region.aws.amazon.com"

        csp = ""
        for src in ["default-src", "script-src", "connect-src", "img-src", "style-src", "base-uri", "form-action"]:
            csp = csp + src + " 'self' " + safeurls + "; "
        csp = csp + "object-src 'none'; frame-ancestors 'none'; block-all-mixed-content"
        
        try:
            #eventheaders = event['headers']
            eventheaders = {}
            eventheaders["Location"] = return_url
            eventheaders["Content-Security-Policy"] = csp
            #for k in strmrespheaders.keys():
            #    eventheaders[k] = strmrespheaders[k]
                
            #print("eventheaders: " + str(eventheaders))
        except Exception as e:
            #print("eventheaders exception e: " + str(e))
            eventheaders = "eventheaders exception"
            
        response = {
            "statusCode": 301,
            "headers": eventheaders
        }
    
    # login.gov returns some resources a nonce and the Chrome browser blocks this.  A work around is to redirect using an html header.    
    if return_html is not None:
        html = '<!DOCTYPE html><html><head><title>redirecting</title>'
        html = html + '<meta http-equiv="refresh" content="0; url='
        html = html + return_url + '">'
        html = html + '</head><body><p>Redirecting</p></body></html>'
        response = {
            "statusCode": 201,
            "body": html,
            "headers": {"Content-Type": "text/html; charset=utf-8"}
        }

    print("response: " + str(response))
    return response
