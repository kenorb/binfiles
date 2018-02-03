#!/usr/bin/env python
#
# Dito GAM 
#
# Copyright 2013 Dito, LLC All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Dito GAM is a command line tool which allows Administrators to control their Google Apps domain and accounts.

With GAM you can programatically create users, turn on/off services for users like POP and Forwarding and much more.
For more information, see http://code.google.com/p/google-apps-manager

"""

__author__ = 'jay@ditoweb.com (Jay Lee)'
__version__ = '3.1'
__license__ = 'Apache License 2.0 (http://www.apache.org/licenses/LICENSE-2.0)'

import sys, os, time, datetime, random, socket, csv, platform, re, calendar, base64, hashlib

try:
  import json
except ImportError:
  import simplejson as json

import httplib2
import apiclient
import apiclient.discovery
import apiclient.errors
from apiclient.http import BatchHttpRequest
import oauth2client.client
import oauth2client.file
import oauth2client.tools

global argv
global quotaUser
quotaUser = None

global directoryObj, reportsObj, oauth2Obj, groupssettingsObj, calendarObj, plusObj, driveObj, licensingObj, adminsettingsObj
directoryObj = reportsObj = oauth2Obj = groupssettingsObj = calendarObj = plusObj = driveObj = licensingObj = adminsettings = None

def convertUTF8(data):
    import collections
    if isinstance(data, str):
      return data
    elif isinstance(data, unicode):
        return data.encode('utf-8')
    elif isinstance(data, collections.Mapping):
        return dict(map(convertUTF8, data.iteritems()))
    elif isinstance(data, collections.Iterable):
        return type(data)(map(convertUTF8, data))
    else:
        return data

def win32_unicode_argv(argv):
  from ctypes import POINTER, byref, cdll, c_int, windll
  from ctypes.wintypes import LPCWSTR, LPWSTR

  GetCommandLineW = cdll.kernel32.GetCommandLineW
  GetCommandLineW.argtypes = []
  GetCommandLineW.restype = LPCWSTR

  CommandLineToArgvW = windll.shell32.CommandLineToArgvW
  CommandLineToArgvW.argtypes = [LPCWSTR, POINTER(c_int)]
  CommandLineToArgvW.restype = POINTER(LPWSTR)

  cmd = GetCommandLineW()
  argc = c_int(0)
  my_argv = CommandLineToArgvW(cmd, byref(argc))
  if argc.value > 0:
    # Remove Python executable and commands if present
    start = argc.value - len(argv)
    return [my_argv[i] for i in xrange(start, argc.value)]

def showUsage():
  doGAMVersion()
  print '''
Usage: gam [OPTIONS]...

Dito GAM. Retrieve or set Google Apps domain,
user, group and alias settings. Exhaustive list of commands
can be found at: http://code.google.com/p/google-apps-manager/wiki

Examples:
gam info domain
gam create user jsmith firstname John lastname Smith password secretpass
gam update user jsmith suspended on
gam.exe update group announcements add member jsmith
...

'''

def getGamPath():
  is_frozen = getattr(sys, 'frozen', '')
  if is_frozen == 'console_exe':
    return os.path.dirname(sys.executable)+'\\'
  if os.name == 'windows' or os.name == 'nt':
    divider = '\\'
  else:
    divider = '/'
  return os.path.dirname(os.path.realpath(sys.argv[0]))+divider

def doGAMVersion():
  import struct
  print 'Dito GAM %s\n%s\nPython %s.%s.%s %s-bit %s\ngoogle-api-python-client %s\n%s %s\nPath: %s' % (__version__, __author__,
                   sys.version_info[0], sys.version_info[1], sys.version_info[2], struct.calcsize('P')*8, sys.version_info[3], apiclient.__version__,
                   platform.platform(), platform.machine(), getGamPath())

def doGAMCheckForUpdates():
  import urllib2
  if os.path.isfile(getGamPath()+'noupdatecheck.txt'): return
  if os.path.isfile(getGamPath()+'lastupdatecheck.txt'):
    f = open(getGamPath()+'lastupdatecheck.txt', 'r')
    last_check_time = int(f.readline())
    f.close()
  else:
    last_check_time = 0
  now_time = calendar.timegm(time.gmtime())
  one_week_ago_time = now_time - 604800
  if last_check_time > one_week_ago_time: return
  try:
    c = urllib2.urlopen('https://gam-update.appspot.com/latest-version.txt?v=%s' % __version__)
    try:
      latest_version = float(c.read())
    except ValueError:
      return
    current_version = float(__version__)
    if latest_version <= current_version:
      f = open(getGamPath()+'lastupdatecheck.txt', 'w')
      f.write(str(now_time))
      f.close()
      return
    a = urllib2.urlopen('https://gam-update.appspot.com/latest-version-announcement.txt?v=%s')
    announcement = a.read()
    sys.stderr.write(announcement)
    visit_gam = raw_input("\n\nHit Y to visit the GAM website and download the latest release. Hit Enter to just continue with this boring old version. GAM won't bother you with this announcemnt for 1 week or you can create a file named noupdatecheck.txt in the same location as gam.py or gam.exe and GAM won't ever check for updates: ")
    if visit_gam.lower() == 'y':
      import webbrowser
      webbrowser.open('http://google-apps-manager.googlecode.com')
      print 'GAM is now exiting so that you can overwrite this old version with the latest release'
      sys.exit(0)
    f = open(getGamPath()+'lastupdatecheck.txt', 'w')
    f.write(str(now_time))
    f.close()
  except urllib2.HTTPError:
    return
  except urllib2.URLError:
    return

def commonAppsObjInit(appsObj):
  #Identify GAM to Google's Servers
  appsObj.source = 'Dito GAM %s / %s / Python %s.%s.%s %s / %s %s /' % (__version__, __author__,
                   sys.version_info[0], sys.version_info[1], sys.version_info[2], sys.version_info[3],
                   platform.platform(), platform.machine())
  #Show debugging output if debug.gam exists
  if os.path.isfile(getGamPath()+'debug.gam'):
    appsObj.debug = True
  return appsObj

def checkErrorCode(e, service):
  try:
    if e[0]['reason'] == 'Token invalid - Invalid token: Stateless token expired':
      keep_domain = service.domain
      tryOAuth(service)
      service.domain = keep_domain
      copes
      return False
  except KeyError:
    pass
  if e[0]['body'][:34] == 'Required field must not be blank: ' or e[0]['body'][:34] == 'These characters are not allowed: ':
    return e[0]['body']
  if e.error_code == 600 and e[0]['body'] == 'Quota exceeded for the current request' or e[0]['reason'] == 'Bad Gateway': 
    return False
  if e.error_code == 600 and e[0]['reason'] == 'Token invalid - Invalid token: Token disabled, revoked, or expired.':
    return '403 - Token disabled, revoked, or expired. Please delete and re-create oauth.txt'
  if e.error_code == 1000: # UnknownError
    return False
  elif e.error_code == 1001: # ServerBusy
    return False
  elif e.error_code == 1002:
    return '1002 - Unauthorized and forbidden'
  elif e.error_code == 1100:
    return '1100 - User deleted recently'
  elif e.error_code == 1200:
    return '1200 - Domain user limit exceeded'
  elif e.error_code == 1201:
    return '1201 - Domain alias limit exceeded'
  elif e.error_code == 1202:
    return '1202 - Domain suspended'
  elif e.error_code == 1203:
    return '1203 - Domain feature unavailable'
  elif e.error_code == 1300:
    if e.invalidInput != '':
      return '1300 - Entity %s exists' % e.invalidInput
    else:
      return '1300 - Entity exists'
  elif e.error_code == 1301:
    if e.invalidInput != '':
      return '1301 - Entity %s Does Not Exist' % e.invalidInput
    else:
      return '1301 - Entity Does Not Exist'
  elif e.error_code == 1302:
    return '1302 - Entity Name Is Reserved'
  elif e.error_code == 1303:
    if e.invalidInput != '':
      return '1303 - Entity %s name not valid' % e.invalidInput
    else:
      return '1303 - Entity name not valid'
  elif e.error_code == 1306:
    if e.invalidInput != '':
      return '1306 - %s has members. Cannot delete.' % e.invalidInput
    else:
      return '1306 - Entity has members. Cannot delete.'
  elif e.error_code == 1400:
    return '1400 - Invalid Given Name'
  elif e.error_code == 1401:
    return '1401 - Invalid Family Name'
  elif e.error_code == 1402:
    return '1402 - Invalid Password'
  elif e.error_code == 1403:
    return '1403 - Invalid Username'
  elif e.error_code == 1404:
    return '1404 - Invalid Hash Function Name'
  elif e.error_code == 1405:
    return '1405 - Invalid Hash Digest Length'
  elif e.error_code == 1406:
    return '1406 - Invalid Email Address'
  elif e.error_code == 1407:
    return '1407 - Invalid Query Parameter Value'
  elif e.error_code == 1408:
    return '1408 - Invalid SSO Signing Key'
  elif e.error_code == 1409:
    return '1409 - Invalid Encryption Public Key'
  elif e.error_code == 1500:
    return '1500 - Too Many Recipients On Email List'
  elif e.error_code == 1501:
    return '1501 - Too Many Aliases For User'
  elif e.error_code == 1502:
    return '1502 - Too Many Delegates For User'
  elif e.error_code == 1601:
    return '1601 - Duplicate Destinations'
  elif e.error_code == 1602:
    return '1602 - Too Many Destinations'
  elif e.error_code == 1603:
    return '1603 - Invalid Route Address'
  elif e.error_code == 1700:
    return '1700 - Group Cannot Contain Cycle'
  elif e.error_code == 1800:
    return '1800 - Invalid Domain Edition'
  elif e.error_code == 1801:
    if e.invalidInput != '':
      return '1801 - Invalid value %s' % e.invalidInput
    else:
      return '1801 - Invalid Value'
  else:
    return '%s: Unknown Error: %s' % (e.error_code, str(e))

def tryOAuth(gdataObject):
  global gdata
  import gdata.apps.service
  global domain
  global customerId
  global quotaUser
  oauth2file = getGamPath()+'oauth2.txt'
  try:
    oauth2file = getGamPath()+os.environ['OAUTHFILE']
  except KeyError:
    pass
  storage = oauth2client.file.Storage(oauth2file)
  credentials = storage.get()
  if credentials is None or credentials.invalid:
    doRequestOAuth()
    credentials = storage.get()
  if credentials.access_token_expired:
    disable_ssl_certificate_validation = False
    if os.path.isfile(getGamPath()+'noverifyssl.txt'):
      disable_ssl_certificate_validation = True
    credentials.refresh(httplib2.Http(ca_certs=getGamPath()+'cacert.pem', disable_ssl_certificate_validation=disable_ssl_certificate_validation))
  gdataObject.additional_headers = {'Authorization': 'Bearer %s' % credentials.access_token}
  try:
    domain = os.environ['GA_DOMAIN'].lower()
  except KeyError:
    domain = credentials.id_token['hd'].lower()
  try:
    customerId = os.environ['CUSTOMER_ID']
  except KeyError:
    customerId = 'my_customer'
  gdataObject.domain = domain
  newhash = hashlib.sha1()
  newhash.update(domain)
  quotaUser = newhash.hexdigest()
  return True

def callGData(service, function, throw_errors=[], **kwargs):
  method = getattr(service, function)
  retries = 10
  for n in range(1, retries+1):
    try:
      return method(**kwargs)
    except gdata.apps.service.AppsForYourDomainException, e:
      terminating_error = checkErrorCode(e, service)
      if e.error_code in throw_errors:
        raise
      if not terminating_error and n != retries:
        wait_on_fail = (2 ** n) if (2 ** n) < 60 else 60
        randomness = float(random.randint(1,1000)) / 1000
        wait_on_fail = wait_on_fail + randomness
        if n > 3: sys.stderr.write('Temp error. Backing off %s seconds...' % (int(wait_on_fail)))
        time.sleep(wait_on_fail)
        if n > 3: sys.stderr.write('attempt %s/%s\n' % (n+1, retries))
        continue
      sys.stderr.write('Error: %s\n' % terminating_error)
      return int(e.error_code)

def callGAPIBatch(service, function, callback, **kwargs):
  global gam_batch
  try:
    gam_batch
  except NameError:
    gam_batch = BatchHttpRequest()
  method = getattr(service, function)
  gam_batch.add(method(quotaUser=quotaUser, prettyPrint=prettyPrint, **kwargs), callback=callback)
  if len(gam_batch._order) == 1000:
    sys.stderr.write('executing batch of 1000 requests...')
    gam_batch.execute()
    gam_batch = BatchHttpRequest()

def callGAPI(service, function, silent_errors=False, throw_reasons=[], retry_reasons=[], **kwargs):
  method = getattr(service, function)
  retries = 10
  for n in range(1, retries+1):
    try:
      return method(quotaUser=quotaUser, prettyPrint=prettyPrint, **kwargs).execute()
    except apiclient.errors.HttpError, e:
      try:
        error = json.loads(e.content)
      except ValueError:
        if not silent_errors:
          print 'ERROR: %s' % e.content
        return 5
      http_status = error['error']['code']
      message = error['error']['errors'][0]['message']
      try:
        reason = error['error']['errors'][0]['reason']
      except KeyError:
        reason = http_status
      if reason in throw_reasons:
        raise e
      if n != retries and (reason in ['rateLimitExceeded', 'userRateLimitExceeded', 'backendError', 'internalError'] or reason in retry_reasons):
        wait_on_fail = (2 ** n) if (2 ** n) < 60 else 60
        randomness = float(random.randint(1,1000)) / 1000
        wait_on_fail = wait_on_fail + randomness
        if n > 3: sys.stderr.write('Temp error %s. Backing off %s seconds...' % (reason, int(wait_on_fail)))
        time.sleep(wait_on_fail)
        if n > 3: sys.stderr.write('attempt %s/%s\n' % (n+1, retries))
        continue
      sys.stderr.write('Error %s: %s - %s\n\n' % (http_status, message, reason))
      return int(http_status)
    except oauth2client.client.AccessTokenRefreshError, e:
      sys.stderr.write('Error: Authentication Token Error - %s' % e)
      return 403
    except httplib2.CertificateValidationUnsupported:
      print '\nError: You don\'t have the Python ssl module installed so we can\'t verify SSL Certificates.\n\nYou can fix this by installing the Python SSL module or you can live on dangerously and turn SSL validation off by creating a file called noverifyssl.txt in the same location as gam.exe / gam.py'
      return 8
    except TypeError, e:
      print 'Error: %s' % e
      return 4

def callGAPIpages(service, function, items, nextPageToken='nextPageToken', page_message=None, message_attribute=None, **kwargs):
  pageToken = None
  all_pages = list()
  total_items = 0
  while True:
    this_page = callGAPI(service=service, function=function, pageToken=pageToken, **kwargs)
    if type(this_page) is int:
      return all_pages
    try:
      page_items = len(this_page[items])
    except KeyError:
      page_items = 0
    total_items += page_items
    if page_message:
      show_message = page_message
      try:
        show_message = show_message.replace('%%num_items%%', str(page_items))
      except KeyError:
        show_message = show_message.replace('%%num_items%%', '0')
      try:
        show_message = show_message.replace('%%total_items%%', str(total_items))
      except KeyError:
        show_message = show_message.replace('%%total_items%%', '0')
      if message_attribute:
        try:
          show_message = show_message.replace('%%first_item%%', str(this_page[items][0][message_attribute]))
          show_message = show_message.replace('%%last_item%%', str(this_page[items][-1][message_attribute]))
        except KeyError:
          show_message = show_message.replace('%%first_item%%', '')
          show_message = show_message.replace('%%last_item%%', '')
      sys.stderr.write(show_message)
    try:
      all_pages += this_page[items]
      pageToken = this_page[nextPageToken]
    except KeyError:
      return all_pages

def getAPIVer(api):
  if api == 'directory':
    return 'directory_v1'
  elif api == 'reports':
    return 'reports_v1'
  elif api == 'oauth2':
    return 'v2'
  elif api == 'groupssettings':
    return 'v1'
  elif api == 'calendar':
    return 'v3'
  elif api == 'plus':
    return 'v1'
  elif api == 'drive':
    return 'v2'
  elif api == 'licensing':
    return 'v1'
  return 'v1'

def getAPIScope(api):
  if api == 'calendar':
    return 'https://www.googleapis.com/auth/calendar'
  elif api == 'drive':
    return 'https://www.googleapis.com/auth/drive'
  elif api == 'plus':
    return 'https://www.googleapis.com/auth/plus.me'

def buildGAPIObject(api):
  object = '%sObj' % api
  try:
    if globals()[object]:
      return globals()[object]
  except KeyError:
    pass
  global domain, customerId, quotaUser, prettyPrint
  oauth2file = getGamPath()+'oauth2.txt'
  try:
    oauth2file = getGamPath()+os.environ['OAUTHFILE']
  except KeyError:
    pass
  storage = oauth2client.file.Storage(oauth2file)
  credentials = storage.get()
  if credentials is None or credentials.invalid:
    doRequestOAuth()
    credentials = storage.get()
  try:
    domain = os.environ['GA_DOMAIN']
  except KeyError:
    domain = credentials.id_token['hd']
  try:
    customerId = os.environ['CUSTOMER_ID']
  except KeyError:
    customerId = 'my_customer'
  newhash = hashlib.sha1()
  newhash.update(domain)
  quotaUser = newhash.hexdigest()
  credentials.user_agent = 'Dito GAM %s / %s / Python %s.%s.%s %s / %s %s /' % (__version__, __author__,
                   sys.version_info[0], sys.version_info[1], sys.version_info[2], sys.version_info[3],
                   platform.platform(), platform.machine())
  disable_ssl_certificate_validation = False
  if os.path.isfile(getGamPath()+'noverifyssl.txt'):
    disable_ssl_certificate_validation = True
  http = httplib2.Http(ca_certs=getGamPath()+'cacert.pem', disable_ssl_certificate_validation=disable_ssl_certificate_validation)
  if os.path.isfile(getGamPath()+'debug.gam'):
    httplib2.debuglevel = 4
    prettyPrint = True
  else:
    prettyPrint = False
  if not os.path.isfile(getGamPath()+'nocache.txt'):
    http = httplib2.Http(ca_certs=getGamPath()+'cacert.pem', disable_ssl_certificate_validation=disable_ssl_certificate_validation, cache='%sgamcache' % getGamPath())
  http = credentials.authorize(http)
  version = getAPIVer(api)
  if api in ['directory', 'reports']:
    my_api = 'admin'
  else:
    my_api = api
  try:
    globals()[object] = apiclient.discovery.build(my_api, version, http=http)
    return globals()[object]
  except apiclient.errors.UnknownApiNameOrVersion:
    if os.path.isfile(getGamPath()+'%s-%s.json' % (api, version)):
      f = file(getGamPath()+'%s-%s.json' % (api, version), 'rb')
      discovery = f.read()
      f.close()
      vars()[object] = apiclient.discovery.build_from_document(discovery, base='https://www.googleapis.com', http=http)
      return vars()[object]
    else:
      raise
  except httplib2.CertificateValidationUnsupported:
    print 'Error: You don\'t have the Python ssl module installed so we can\'t verify SSL Certificates. You can fix this by installing the Python SSL module or you can live on the edge and turn SSL validation off by creating a file called noverifyssl.txt in the same location as gam.exe / gam.py'
    sys.exit(8)

def buildGAPIServiceObject(api, act_as=None):
  global prettyPrint
  oauth2servicefile = getGamPath()+'oauth2service'
  try:
    oauth2servicefile = getGamPath()+os.environ['OAUTHSERVICEFILE']
  except KeyError:
    pass
  oauth2servicefiletxt = '%s.txt' % oauth2servicefile
  oauth2servicefilep12 = '%s.p12' % oauth2servicefile
  try:
    oa2f = open(oauth2servicefiletxt, 'rb')
    SERVICE_ACCOUNT_EMAIL = oa2f.readline()
    oa2f.close()
  except IOError:
    while True:
      SERVICE_ACCOUNT_EMAIL = raw_input("Please enter the email address for your service account: ")
      if SERVICE_ACCOUNT_EMAIL.find('@') != -1:
        break
      else:
        print 'Error: that\'s not a valid email address'
    oa2f = open(oauth2servicefiletxt, 'wb')
    oa2f.write(SERVICE_ACCOUNT_EMAIL)
    oa2f.close()
  try:
    f = file(oauth2servicefilep12, 'rb')
  except IOError, e:
    print e
    sys.exit(2)
  key = f.read()
  f.close()
  scope = getAPIScope(api)
  if act_as == None:
    credentials = oauth2client.client.SignedJwtAssertionCredentials(SERVICE_ACCOUNT_EMAIL, key, scope=scope)
  else:
    credentials = oauth2client.client.SignedJwtAssertionCredentials(SERVICE_ACCOUNT_EMAIL, key, scope=scope, sub=act_as)
  disable_ssl_certificate_validation = False
  if os.path.isfile(getGamPath()+'noverifyssl.txt'):
    disable_ssl_certificate_validation = True
  http = httplib2.Http(ca_certs=getGamPath()+'cacert.pem', disable_ssl_certificate_validation=disable_ssl_certificate_validation)
  if os.path.isfile(getGamPath()+'debug.gam'):
    httplib2.debuglevel = 4
    prettyPrint = True
  else:
    prettyPrint = False
  if not os.path.isfile(getGamPath()+'nocache.txt'):
    http = httplib2.Http(ca_certs=getGamPath()+'cacert.pem', disable_ssl_certificate_validation=disable_ssl_certificate_validation, cache='%sgamcache' % getGamPath())
  http = credentials.authorize(http)
  version = getAPIVer(api)
  try:
    return apiclient.discovery.build(api, version, http=http)
  except oauth2client.client.AccessTokenRefreshError, e:
    print e
    sys.exit(4)

def getEmailSettingsObject():
  import gdata.apps.emailsettings.service
  emailsettings = gdata.apps.emailsettings.service.EmailSettingsService()
  if not tryOAuth(emailsettings):
    doRequestOAuth()
    tryOAuth(emailsettings)
  emailsettings = commonAppsObjInit(emailsettings)
  return emailsettings

def getAdminSettingsObject():
  import gdata.apps.adminsettings.service
  adminsettings = gdata.apps.adminsettings.service.AdminSettingsService()
  if not tryOAuth(adminsettings):
    doRequestOAuth()
    tryOAuth(adminsettings)
  adminsettings = commonAppsObjInit(adminsettings)
  return adminsettings
  
def getAuditObject():
  import gdata.apps.audit.service
  auditObj = gdata.apps.audit.service.AuditService()
  if not tryOAuth(auditObj):
    doRequestOAuth()
    tryOAuth(auditObj)
  auditObj = commonAppsObjInit(auditObj)
  return auditObj

def getResCalObject():
  import gdata.apps.res_cal.service
  resCalObj = gdata.apps.res_cal.service.ResCalService()
  if not tryOAuth(resCalObj):
    doRequestOAuth()
    tryOAuth(resCalObj)
  resCalObj = commonAppsObjInit(resCalObj)
  return resCalObj

def geturl(url, dst):
  import urllib2
  u = urllib2.urlopen(url)
  f = open(dst, 'wb')
  meta = u.info()
  file_size = int(meta.getheaders("Content-Length")[0])
  file_size_dl = 0
  block_sz = 8192
  while True:
    buffer = u.read(block_sz)
    if not buffer:
        break
    file_size_dl += len(buffer)
    f.write(buffer)
    status = r"%10d  [%3.2f%%]" % (file_size_dl, file_size_dl * 100. / file_size)
    status = status + chr(8)*(len(status)+1)
    print status,
  f.close()

def showReport():
  report = argv[2].lower()
  reportsObj = buildGAPIObject('reports')
  date = filters = parameters = actorIpAddress = startTime = endTime = eventName = None
  to_drive = False
  userKey = 'all'
  i = 3
  while i < len(argv):
    if argv[i].lower() == 'date':
      date = argv[i+1]
      i += 2
    elif argv[i].lower() == 'start':
      startTime = argv[i+1]
      i += 2
    elif argv[i].lower() == 'end':
      endTime = argv[i+1]
      i += 2
    elif argv[i].lower() == 'event':
      eventName = argv[i+1]
      i += 2
    elif argv[i].lower() == 'user':
      userKey = argv[i+1]
      i += 2
    elif argv[i].lower() in ['filter', 'filters']:
      filters = argv[i+1]
      i += 2
    elif argv[i].lower() in ['fields', 'parameters']:
      parameters = argv[i+1]
      i += 2
    elif argv[i].lower() == 'ip':
      actorIpAddress = argv[i+1]
      i += 2
    elif argv[i].lower() == 'todrive':
      to_drive = True
      i += 1
    else:
      print 'Error: did not expect %s as an argument to "gam report"' % argv[i]
      return 3
  try_date = date
  if try_date == None:
    try_date = datetime.date.today()
  if report in ['users', 'user']:
    while True:
      try:
        page_message = 'Got %%num_items%% users\n'
        usage = callGAPIpages(service=reportsObj.userUsageReport(), function='get', items='usageReports', page_message=page_message, throw_reasons=['invalid'], date=str(try_date), userKey=userKey, filters=filters, parameters=parameters)
        break
      except apiclient.errors.HttpError, e:
        error = json.loads(e.content)
      try:
        message = error['error']['errors'][0]['message']
      except KeyError:
        raise
      match_date = re.match('Data for dates later than (.*) is not yet available. Please check back later', message)
      if not match_date:
        print 'Error: %s' % message
        return 4
      else:
        try_date = match_date.group(1)
    user_attributes = []
    titles = ['email', 'date']
    for user_report in usage:
      row = {'email': user_report['entity']['userEmail'], 'date': str(try_date)}
      try:
        for report_item in user_report['parameters']:
          items = report_item.values()
          name = items[1]
          value = items[0]
          if not name in titles:
            titles.append(name)
          row[name] = value
      except KeyError:
        pass
      user_attributes.append(row)
    header = {}
    for title in titles:
      header[title] = title
    user_attributes.insert(0, header)
    output_csv(user_attributes, titles, 'User Reports - %s' % try_date, to_drive)
  elif report in ['customer', 'customers', 'domain']:
    while True:
      try:
        usage = callGAPIpages(service=reportsObj.customerUsageReports(), function='get', items='usageReports', throw_reasons=['invalid'], date=str(try_date), parameters=parameters)
        break
      except apiclient.errors.HttpError, e:
        error = json.loads(e.content)
      try:
        message = error['error']['errors'][0]['message']
      except KeyError:
        raise
      match_date = re.match('Data for dates later than (.*) is not yet available. Please check back later', message)
      if not match_date:
        print 'Error: %s' % message
        return 4
      else:
        try_date = match_date.group(1)
    cust_attributes = [{'name': 'name', 'value': 'value', 'client_id': 'client_id'}]
    titles = ['name', 'value', 'client_id']
    for item in usage[0]['parameters']:
      name = item['name']
      try:
        value = item['intValue']
      except KeyError:
        if name == 'accounts:authorized_apps':
          auth_apps = list()
          for subitem in item['msgValue']:
            app = dict()
            for an_item in subitem:
              if an_item == 'client_name':
                app['name'] = 'App: %s' % subitem[an_item]
              elif an_item == 'num_users':
                app['value'] = '%s users' % subitem[an_item]
              elif an_item == 'client_id':
                app['client_id'] = subitem[an_item]
            auth_apps.append(app)
        continue
      cust_attributes.append({'name': name, 'value': value})
    for app in auth_apps: # put apps at bottom
      cust_attributes.append(app)
    output_csv(csv_list=cust_attributes, titles=titles, list_type='Customer Report - %s' % try_date, todrive=to_drive)
  elif report in ['doc', 'docs']:
    doc_activities = callGAPIpages(service=reportsObj.activities(), function='list', items='items', applicationName='docs', userKey=userKey, actorIpAddress=actorIpAddress, startTime=startTime, endTime=endTime, eventName=eventName, filters=filters)
    doc_attr = [{'user': 'user', 'event': 'event', 'doc_id': 'doc_id', 'time': 'time', 'ip': 'ip'}]
    titles = ['user', 'event', 'doc_id', 'time', 'ip']
    for doc_activity in doc_activities:
      for event in doc_activity['events']:
        for parameter in event['parameters']:
          row = {'user': doc_activity['actor']['email'],
                 'event': event['name'],
                 'doc_id': parameter['value'],
                 'time': doc_activity['id']['time']}
          try:
            row['ip'] = doc_activity['ipAddress']
          except KeyError:
            row['ip'] = 'unknown'
          doc_attr.append(row)
    output_csv(doc_attr, titles, 'Docs Activity Report', to_drive)
  elif report == 'admin':
    admin_activity = callGAPIpages(service=reportsObj.activities(), function='list', items='items', applicationName='admin', userKey=userKey, actorIpAddress=actorIpAddress, startTime=startTime, endTime=endTime, eventName=eventName, filters=filters)
    admin_attr = []
    titles = ['time', 'user', 'event', 'ip']
    for activity in admin_activity:
      for event in activity['events']:
        row = {}
        try:
          row['event'] = event['name']
        except KeyError:
          pass
        try:
          row[ 'time'] = activity['id']['time']
        except KeyError:
          pass
        try:
          row[ 'user'] = activity['actor']['email']
        except KeyError:
          pass
        try:
          row['ip'] = activity['ipAddress']
        except KeyError:
          row['ip'] = 'unknown'
        try:
          for parameter in event['parameters']:
            try:
              if not parameter['name'].lower() in titles:
                titles.append(parameter['name'].lower())
              row[parameter['name'].lower()] = parameter['value']
            except KeyError:
              pass
        except KeyError:
          pass
        admin_attr.append(row)
    header = {}
    for title in titles:
      header[title] = title
    admin_attr.insert(0, header)
    output_csv(admin_attr, titles, 'Admin Audit Report', to_drive)
  elif report in ['login', 'logins']:
    login_activity = callGAPIpages(service=reportsObj.activities(), function='list', items='items', applicationName='login', userKey=userKey, actorIpAddress=actorIpAddress, startTime=startTime, endTime=endTime, eventName=eventName, filters=filters)
    login_attr = []
    titles = ['time', 'user', 'event', 'ip']
    for activity in login_activity:
      for event in activity['events']:
        row = {}
        try:
          row['event'] = event['name']
        except KeyError:
          pass
        try:
          row[ 'time'] = activity['id']['time']
        except KeyError:
          pass
        try:
          row[ 'user'] = activity['actor']['email']
        except KeyError:
          pass
        try:
          row['ip'] = activity['ipAddress']
        except KeyError:
          row['ip'] = 'unknown'
        try:
          for parameter in event['parameters']:
            try:
              if not parameter['name'].lower() in titles:
                titles.append(parameter['name'].lower())
              row[parameter['name'].lower()] = parameter['value']
            except KeyError:
              pass
        except KeyError:
          pass
        login_attr.append(row)
    header = {}
    for title in titles:
      header[title] = title
    login_attr.insert(0, header)
    output_csv(login_attr, titles, 'Login Audit Report', to_drive)

def doDelegates(users):
  emailsettings = getEmailSettingsObject()
  if argv[4].lower() == 'to':
    delegate = argv[5].lower()
    if not delegate.find('@') > 0:
      delegate_domain = domain.lower()
      delegate_email = '%s@%s' % (delegate, delegate_domain)
    else:
      delegate_domain = delegate[delegate.find('@')+1:].lower()
      delegate_email = delegate
  else:
    showUsage()
    exit(6)
  count = len(users)
  i = 1
  for delegator in users:
    if delegator.find('@') > 0:
      delegator_domain = delegator[delegator.find('@')+1:].lower()
      delegator_email = delegator
      delegator = delegator[:delegator.find('@')]
    else:
      delegator_domain = domain.lower()
      delegator_email = '%s@%s' % (delegator, delegator_domain)
    emailsettings.domain = delegator_domain
    print "Giving %s delegate access to %s (%s of %s)" % (delegate_email, delegator_email, i, count)
    i += 1
    delete_alias = False
    if delegate_domain == delegator_domain:
      use_delegate_address = delegate_email
    else:
      # Need to use an alias in delegator domain, first check to see if delegate already has one...
      directoryObj = buildGAPIObject('directory')
      aliases = callGAPI(service=directoryObj.users().aliases(), function='list', userKey=delegate_email)
      found_alias_in_delegator_domain = False
      try:
        for alias in aliases['aliases']:
          alias_domain = alias['alias'][alias['alias'].find('@')+1:].lower()
          if alias_domain == delegator_domain:
            use_delegate_address = alias['alias']
            print '  Using existing alias %s for delegation' % use_delegate_address
            found_alias_in_delegator_domain = True
            break
      except KeyError:
        pass
      if not found_alias_in_delegator_domain:
        delete_alias = True
        use_delegate_address = '%s@%s' % (''.join(random.sample('abcdefghijklmnopqrstuvwxyz0123456789', 25)), delegator_domain)
        print '  Giving %s temporary alias %s for delegation' % (delegate_email, use_delegate_address)
        create_result = callGAPI(service=cd.users().aliases(), function='insert', userKey=delegate_email, body={'alias': use_delegate_address})
        time.sleep(5)
    retries = 10
    for n in range(1, retries+1):
      try:
        callGData(service=emailsettings, function='CreateDelegate', throw_errors=[600, 1000, 1001], delegate=use_delegate_address, delegator=delegator)
        break
      except gdata.apps.service.AppsForYourDomainException, e:
        # 1st check to see if delegation already exists (causes 1000 error on create when using alias)
        get_delegates = callGData(service=emailsettings, function='GetDelegates', delegator=delegator)
        for get_delegate in get_delegates:
          if get_delegate['address'].lower() == delegate_email: # Delegation is already in place
            print 'That delegation is already in place...'
            if delete_alias:
              print '  Deleting temporary alias...'
              doDeleteAlias(alias_email=use_delegate_address)
            return 0 # Emulate functionality of duplicate delegation between users in same domain, returning clean
        # Now check if either user account is suspended or requires password change
        directoryObj = buildGAPIObject('directory')
        delegate_user_details = callGAPI(service=directoryObj.users(), function='get', userKey=delegate_email)
        delegator_user_details = callGAPI(service=directoryObj.users(), function='get', userKey=delegator_email)
        if delegate_user_details['suspended'] == True:
          sys.stderr.write('ERROR: User %s is suspended. You must unsuspend for delegation.\n' % delegate_email)
          if delete_alias:
            doDeleteAlias(alias_email=use_delegate_address)
          return 5
        if delegator_user_details['suspended'] == True:
          sys.stderr.write('ERROR: User %s is suspended. You must unsuspend for delegation.\n' % delegator_email)
          if delete_alias:
            doDeleteAlias(alias_email=use_delegate_address)
          return 5
        if delegate_user_details['changePasswordAtNextLogin'] == True:
          sys.stderr.write('ERROR: User %s is required to change password at next login. You must change password or clear changepassword flag for delegation.\n' % delegate_email)
          if delete_alias:
            doDeleteAlias(alias_email=use_delegate_address)
          return 5
        if delegator_user_details['changePasswordAtNextLogin'] == True:
          sys.stderr.write('ERROR: User %s is required to change password at next login. You must change password or clear changepassword flag for delegation.\n' % delegator_email)
          if delete_alias:
            doDeleteAlias(alias_email=use_delegate_address)
          return 5
        
        # Guess it was just a normal backoff error then?
        if n == retries:
          sys.stderr.write(' - giving up.')
          return e.error_code
        wait_on_fail = (2 ** n) if (2 ** n) < 60 else 60
        randomness = float(random.randint(1,1000)) / 1000
        wait_on_fail = wait_on_fail + randomness
        if n > 3: sys.stderr.write('Temp error. Backing off %s seconds...' % (int(wait_on_fail)))
        time.sleep(wait_on_fail)
        if n > 3: sys.stderr.write('attempt %s/%s\n' % (n+1, retries))
    time.sleep(10) # on success, sleep 10 seconds before exiting or moving on to next user to prevent ghost delegates
    if delete_alias:
      doDeleteAlias(alias_email=use_delegate_address)

def getDelegates(users):
  emailsettings = getEmailSettingsObject()
  csv_format = False
  try:
    if argv[5].lower() == 'csv':
      csv_format = True
  except IndexError:
    pass
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain
    sys.stderr.write("Getting delegates for %s...\n" % (user + '@' + emailsettings.domain))
    delegates = callGData(service=emailsettings, function='GetDelegates', delegator=user)
    if type(delegates) is int:
      continue
    try:
      for delegate in delegates:
        if csv_format:
          print '%s,%s,%s' % (user + '@' + emailsettings.domain, delegate['address'], delegate['status'])
        else:
          print "Delegator: %s\n Delegate: %s\n Status: %s\n Delegate Email: %s\n Delegate ID: %s\n" % (user, delegate['delegate'], delegate['status'], delegate['address'], delegate['delegationId'])
    except TypeError:
      pass

def deleteDelegate(users):
  emailsettings = getEmailSettingsObject()
  delegate = argv[5]
  if not delegate.find('@') > 0:
    if users[0].find('@') > 0:
      delegatedomain = users[0][users[0].find('@')+1:]
    else:
      delegatedomain = domain
    delegate = delegate+'@'+delegatedomain
  count = len(users)
  i = 1
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    print "Deleting %s delegate access to %s (%s of %s)" % (delegate, user+'@'+emailsettings.domain, i, count)
    i += 1
    callGData(service=emailsettings, function='DeleteDelegate', delegate=delegate, delegator=user)

def changeCalendarAttendees(users):
  calendarObj = buildGAPIServiceObject('calendar', users[0])
  count = len(users)
  do_it = True
  i = 5
  allevents = False
  start_date = end_date = None
  while len(argv) > i:
    if argv[i].lower() == 'csv':
      csv_file = argv[i+1]
      i += 2
    elif argv[i].lower() == 'dryrun':
      do_it = False
      i += 1
    elif argv[i].lower() == 'start':
      start_date = argv[i+1]
      i += 2
    elif argv[i].lower() == 'end':
      end_date = argv[i+1]
      i += 2
    elif argv[i].lower() == 'allevents':
      allevents = True
      i += 1
    else:
      showUsage()
      print '%s is not a valid argument.'
      return 3
  attendee_map = dict()
  csvfile = csv.reader(open(csv_file, 'rb'))
  for row in csvfile:
    attendee_map[row[0].lower()] = row[1].lower()
  for user in users:
    sys.stdout.write('Checking user %s\n' % user)
    if user.find('@') == -1:
      user = '%s@%s' % (user, domain)
    cal = buildGAPIServiceObject('calendar', user)
    page_token = None
    while True:
      events_page = callGAPI(service=calendarObj.events(), function='list', calendarId=user, pageToken=page_token, timeMin=start_date, timeMax=end_date, showDeleted=False, showHiddenInvitations=False)
      print 'Got %s items' % len(events_page.get('items', []))
      for event in events_page.get('items', []):
        if event['status'] == u'cancelled':
          #print ' skipping cancelled event'
          continue
        try:
          event_summary = str(event['summary'])
        except (KeyError, UnicodeEncodeError, UnicodeDecodeError):
          event_summary = event['id']
        try:
          if not allevents and event['organizer']['email'].lower() != user:
            #print ' skipping not-my-event %s' % event_summary
            continue          
        except KeyError,e:
          pass # no email for organizer
        needs_update = False
        try:
          for attendee in event['attendees']:
            try:
              if attendee['email'].lower() in attendee_map.keys():
                old_email = attendee['email'].lower()
                new_email = attendee_map[attendee['email'].lower()]
                print ' SWITCHING attendee %s to %s for %s' % (old_email, new_email, event_summary)
                event['attendees'].remove(attendee)
                event['attendees'].append({'email': new_email})
                needs_update = True
            except KeyError: # no email for that attendee
              pass
        except KeyError:
          continue # no attendees
        if needs_update:
          body = dict()
          body['attendees'] = event['attendees']
          print 'UPDATING %s' % event_summary
          if do_it:
            callGAPI(service=calendarObj.events(), function='patch', calendarId=user, eventId=event['id'], sendNotifications=False, body=body)
          else:
            print ' not pulling the trigger.'
        #else:
        #  print ' no update needed for %s' % event_summary
      try:
        page_token = events_page['nextPageToken']
      except KeyError:
        break

def deleteCalendar(users):
  calendarObj = buildGAPIServiceObject('calendar', users[0])
  calendarId = argv[5]
  if calendarId.find('@') == -1:
    calendarId = '%s@%s' % (calendarId, domain)
  count = len(users)
  i = 1
  for user in users:
    if user.find('@') == -1:
      user = '%s@%s' % (user, domain)
    calendarObj = buildGAPIServiceObject('calendar', user)
    print "Deleting %s calendar for %s (%s of %s)" % (calendarId, user, i, count)
    callGAPI(service=calendarObj.calendarList(), function='delete', calendarId=calendarId)
    i += 1

def addCalendar(users):
  calendarObj = buildGAPIServiceObject('calendar', users[0])
  body = dict()
  body['defaultReminders'] = list()
  body['id'] = argv[5]
  if body['id'].find('@') == -1:
    body['id'] = '%s@%s' % (body['id'], domain)
  body['selected'] = True
  body['hidden'] = False
  i = 6
  while i < len(argv):
    if argv[i].lower() == 'selected':
      if argv[i+1].lower() == 'true':
        body['selected'] = True
      elif argv[i+1].lower() == 'false':
        body['selected'] = False
      else:
        showUsage()
        print 'Value for selected must be true or false, not %s' % argv[i+1]
        exit(4)
      i += 2
    elif argv[i].lower() == 'hidden':
      if argv[i+1].lower() == 'true':
        body['hidden'] = True
      elif argv[i+1].lower() == 'false':
        body['hidden'] = False
      else:
        showUsage()
        print 'Value for hidden must be true or false, not %s' % argv[i+1]
        exit(4)
      i += 2
    elif argv[i].lower() == 'reminder':
      method = argv[i+1].lower()
      try:
        minutes = int(argv[i+2])
      except ValueError:
        'Error: Reminder time must be specified in minutes, got %s' % argv[i+2]
        return 22
      if (method != 'email' and method != 'sms' and method != 'popup'):
        'Error: Method must be email, sms or popup. Got %s' % method
        return 23
      body['defaultReminders'].append({'method': method, 'minutes': minutes})
      i = i + 3
    elif argv[i].lower() == 'summary':
      body['summaryOverride'] = argv[i+1]
      i += 2
    elif argv[i].lower() == 'colorindex':
      body['colorId'] = str(argv[i+1])
      i += 2
    elif argv[i].lower() == 'backgroundcolor':
      body['backgroundColor'] = argv[i+1]
      i += 2
    elif argv[i].lower() == 'foregroundcolor':
      body['foregroundColor'] = argv[i+1]
      i += 2
    else:
      showUsage()
      print '%s is not a valid argument for "gam add calendar"' % argv[i]
  i = 1
  count = len(users)
  for user in users:
    if user.find('@') == -1:
      user = '%s@%s' % (user, domain)
    print "Subscribing %s to %s calendar (%s of %s)" % (user, body['id'], i, count)
    cal = buildGAPIServiceObject('calendar', user)
    callGAPI(service=calendarObj.calendarList(), function='insert', body=body)
    i += 1

def updateCalendar(users):
  calendarId = argv[5]
  i = 6
  body = dict()
  body['id'] = calendarId
  while i < len(argv):
    if argv[i].lower() == 'selected':
      if argv[i+1].lower() == 'true':
        body['selected'] = True
      elif argv[i+1].lower() == 'false':
        body['selected'] = False
      else:
        showUsage()
        print 'Value for selected must be true or false, not %s' % argv[i+1]
        exit(4)
      i += 2
    elif argv[i].lower() == 'hidden':
      if argv[i+1].lower() == 'true':
        body['hidden'] = True
      elif argv[i+1].lower() == 'false':
        body['hidden'] = False
      else:
        showUsage()
        print 'Value for hidden must be true or false, not %s' % argv[i+1]
        exit(4)
      i += 2
    elif argv[i].lower() == 'summary':
      body['summaryOverride'] = argv[i+1]
      i += 2
    elif argv[i].lower() == 'colorindex':
      body['colorId'] = str(argv[i+1])
      i += 2
    elif argv[i].lower() == 'backgroundcolor':
      body['backgroundColor'] = argv[i+1]
      i += 2
    elif argv[i].lower() == 'foregroundcolor':
      body['foregroundColor'] = argv[i+1]
      i += 2
    elif argv[i].lower() == 'reminder':
      method = argv[i+1].lower()
      try:
        minutes = int(argv[i+2])
      except ValueError:
        'Error: Reminder time must be specified in minutes, got %s' % argv[i+2]
        return 22
      if (method != 'email' and method != 'sms' and method != 'popup'):
        'Error: Method must be email, sms or popup. Got %s' % method
        return 23
      try:
        body['defaultReminders'].append({'method': method, 'minutes': minutes})
      except KeyError:
        body['defaultReminders'] = [{'method': method, 'minutes': minutes}]
      i = i + 3    
    else:
      showUsage()
      print '%s is not a valid argument for "gam update calendar"' % argv[i]
  i = 1
  count = len(users)
  for user in users:
    print "Updating %s's subscription to calendar %s (%s of %s)" % (user, calendarId, i, count)
    calendarObj = buildGAPIServiceObject('calendar', user)
    callGAPI(service=calendarObj.calendarList(), function='update', calendarId=calendarId, body=body)

def doCalendarShowACL():
  show_cal = argv[2]
  calendarObj = buildGAPIObject('calendar')
  if show_cal.find('@') == -1:
    show_cal = '%s@%s' % (show_cal, domain)
  acls = callGAPI(service=calendarObj.acl(), function='list', calendarId=show_cal)
  if type(acls) is int:
    return
  try:
    for rule in acls['items']:
      print '  Scope %s - %s' % (rule['scope']['type'], rule['scope']['value'])
      print '  Role: %s' % (rule['role'])
      print ''
  except IndexError:
    pass

def doCalendarAddACL(calendarId=None, act_as=None, role=None, scope=None, entity=None):
  if act_as != None:
    calendarObj = buildGAPIServiceObject('calendar', act_as)
  else:
    calendarObj = buildGAPIObject('calendar')
  body = dict()
  body['scope'] = dict()
  if calendarId == None:
    calendarId = argv[2]
  if calendarId.find('@') == -1:
    calendarId = '%s@%s' % (calendarId, domain)
  if role != None:
    body['role'] = role
  else:
    body['role'] = argv[4].lower()
  if body['role'] != 'freebusy' and body['role'] != 'read' and body['role'] != 'editor' and body['role'] != 'owner' and body['role'] != 'none':
    print 'Error: Role must be freebusy, read, editor or owner. Not %s' % body['role']
    sys.exit (33)
  if body['role'] == 'freebusy':
    body['role'] = 'freeBusyReader'
  elif body['role'] == 'read':
    body['role'] = 'reader'
  elif body['role'] == 'editor':
    body['role'] = 'writer'
  if scope != None:
    body['scope']['type'] = scope
  else:
    body['scope']['type'] = argv[5].lower()
  i = 6
  if body['scope']['type'] not in ['default', 'user', 'group', 'domain']:
    body['scope']['type'] = 'user'
    i = 5
  try:
    if entity != None and body['scope']['type'] != 'default':
      body['scope']['value'] = entity
    else:
      body['scope']['value'] = argv[i].lower()
    if (body['scope']['type'] in ['user', 'group']) and body['scope']['value'].find('@') == -1:
      body['scope']['value'] = '%s@%s' % (body['scope']['value'], domain)
  except IndexError:
    pass
  if body['scope']['type'] == 'domain':
    try:
      body['scope']['value'] = argv[6].lower()
    except KeyError:
      body['scope']['value'] = domain
  callGAPI(service=calendarObj.acl(), function='insert', calendarId=calendarId, body=body)

def doCalendarUpdateACL():
  calendarId = argv[2]
  role = argv[4].lower()
  scope = argv[5].lower()
  try:
    entity = argv[6].lower()
  except IndexError:
    entity = None
  doCalendarAddACL(calendarId=calendarId, role=role, scope=scope, entity=entity)

def doCalendarDelACL():
  calendarId = argv[2]
  entity = argv[4].lower()
  scope = 'user'
  if entity == 'domain':
    scope = 'domain'
  elif entity == 'default':
    scope = 'default'
    entity = ''
  doCalendarAddACL(calendarId=calendarId, role='none', scope=scope, entity=entity)

def doCalendarWipeData():
  calendarId = argv[2]
  calendarObj = buildGAPIServiceObject('calendar', calendarId)
  if calendarId.find('@') == -1:
    calendarId = '%s@%s' % (calendarId, domain)
  callGAPI(service=calendarObj.calendars(), function='clear', calendarId=calendarId)

def doProfile(users):
  if argv[4].lower() in ['share', 'shared', 'show']:
    body = {'includeInGlobalAddressList': True}
  elif argv[4].lower() in ['unshare', 'unshared', 'hide']:
    body = {'includeInGlobalAddressList': False}
  else:
    print 'Error: profile should be share or unshare. Got %s' % argv[4]
    sys.exit(3)
  directoryObj = buildGAPIObject('directory')
  count = len(users)
  i = 1
  for user in users:
    if user[:4].lower() == 'uid:':
      user = user[4:]
    elif user.find('@') == -1:
      user = '%s@%s' % (user, domain)
    print 'Setting Profile Sharing to %s for %s (%s of %s)' % (body['includeInGlobalAddressList'], user, i, count)
    callGAPIBatch(service=directoryObj.users(), function='patch', callback=generic_callback, userKey=user, body=body)
    i += 1

def show_profile_callback(request_id, response, exception):
  if exception is not None:
    print exception
  else:
    print 'User %s include in GAL is %s' % (response['primaryEmail'], response['includeInGlobalAddressList'])

def showProfile(users):
  i = 1
  count = len(users)
  directoryObj = buildGAPIObject('directory')
  for user in users:
    if user[:4].lower() == 'uid:':
      user = user[4:]
    elif user.find('@') == -1:
      user = '%s@%s' % (user, domain)
    callGAPIBatch(service=directoryObj.users(), function='get', callback=show_profile_callback, userKey=user, fields='primaryEmail,includeInGlobalAddressList')
    i += 1

def update_photo_callback(request_id, response, exception):
  if exception is not None:
    print exception
  else:
    print response

def doPhoto(users):
  directoryObj = buildGAPIObject('directory')
  i = 1
  count = len(users)
  for user in users:
    if user[:4].lower() == 'uid:':
      user = user[4:]
    elif user.find('@') == -1:
      user = '%s@%s' % (user, domain)
    filename = argv[5].replace('#user#', user)
    print "Updating photo for %s with %s (%s of %s)" % (user, filename, i, count)
    i += 1
    if re.match('^(ht|f)tps?://.*$', filename):
      import urllib2
      try:
        f = urllib2.urlopen(filename)
        image_data = f.read()
      except urllib2.HTTPError, e:
        print e
        continue
    else:
      try:
        f = open(filename, 'rb')
        image_data = f.read()
        f.close()
      except IOError, e:
        print ' couldn\'t open %s: %s' % (filename, e.strerror)
        continue
    image_data = base64.b64encode(image_data)
    image_data = image_data.replace('/', '_')
    image_data = image_data.replace('+', '-')
    body = {'photoData': image_data}
    callGAPIBatch(service=directoryObj.users().photos(), function='update', callback=update_photo_callback, userKey=user, body=body)

def getPhoto(users):
  directoryObj = buildGAPIObject('directory')
  i = 1
  count = len(users)
  for user in users:
    if user[:4].lower() == 'uid:':
      user = user[4:]
    elif user.find('@') == -1:
      user = '%s@%s' % (user, domain)
    filename = '%s.jpg' % user
    print "Saving photo to %s (%s/%s)" % (filename, i, count)
    i += 1
    try:
      photo = callGAPI(service=directoryObj.users().photos(), function='get', throw_reasons=['notFound'], userKey=user)
    except apiclient.errors.HttpError:
      print ' no photo for %s' % user
      continue
    try:
      photo_data = photo['photoData']
      photo_data = photo_data.replace('_', '/')
      photo_data = photo_data.replace('-', '+')
      photo_data = base64.b64decode(photo_data)
    except KeyError:
      print ' no photo for %s' % user
      continue
    photo_file = open(filename, 'wb')
    photo_file.write(photo_data)
    photo_file.close()

def delete_photo_callback(request_id, response, exception):
  if exception is not None:
    print exception
  else:
    print response

def deletePhoto(users):
  directoryObj = buildGAPIObject('directory')
  i = 1
  count = len(users)
  for user in users:
    if user[:4].lower() == 'uid:':
      user = user[4:]
    elif user.find('@') == -1:
      user = '%s@%s' % (user, domain)
    print "Deleting photo for %s (%s of %s)" % (user, i, count)
    callGAPIBatch(service=directoryObj.users().photos(), function='delete', callback=delete_photo_callback, userKey=user)
    i += 1

def showCalendars(users):
  for user in users:
    calendarObj = buildGAPIServiceObject('calendar', user)
    feed = callGAPI(service=calendarObj.calendarList(), function='list')
    if type(feed) is int:
      continue
    for calendar in feed['items']:
      print '  Name: %s' % calendar['id']
      print '  Summary: %s' % calendar['summary']
      try:
        print '    Description: %s' % calendar['description']
      except KeyError:
        print '    Description: '
      print '    Access Level: %s' % calendar['accessRole']
      print '    Timezone: %s' % calendar['timeZone']
      try:
        print '    Location: %s' % calendar['location']
      except KeyError:
        pass
      try:
        print '    Hidden: %s' % calendar['hidden']
      except KeyError:
        print '    Hidden: False'
      try:
        print '    Selected: %s' % calendar['selected']
      except KeyError:
        print '    Selected: False'
      print '    Default Reminders:'
      try:
        for reminder in calendar['defaultReminders']:
          print '      Type: %s  Minutes: %s' % (reminder['method'], reminder['minutes'])
      except KeyError:
        pass
      print ''

def showCalSettings(users):
  for user in users:
    for user in users:
      calendarObj = buildGAPIServiceObject('calendar', user)
      feed = callGAPI(service=calendarObj.settings(), function='list')
      if type(feed) is int:
        continue
      for setting in feed['items']:
        print '%s: %s' % (setting['id'], setting['value'])

def showDriveSettings(users):
  dont_show = ['kind', 'selfLink', 'exportFormats', 'importFormats', 'maxUploadSizes', 'additionalRoleInfo', 'etag', 'features', 'user', 'isCurrentAppInstalled']
  count = 1
  drive_attr = []
  titles = ['email',]
  for user in users:
    sys.stderr.write('Getting Drive settings for %s (%s of %s)\n' % (user, count, len(users)))
    count += 1
    driveObj = buildGAPIServiceObject('drive', user)
    feed = callGAPI(service=driveObj.about(), function='get')
    if type(feed) is int:
        continue
    row = {'email': user}
    for setting in feed:
      if setting in dont_show:
        continue
      if setting.find('quota') != -1:
        feed[setting] = '%smb' % (int(feed[setting]) / 1024 / 1024)
      row[setting] = feed[setting]
      if setting not in titles:
        titles.append(setting)
    drive_attr.append(row)
  headers = {}
  for title in titles:
    headers[title] = title
  drive_attr.insert(0, headers)
  output_csv(drive_attr, titles, 'User Drive Settings', False)

def showDriveFiles(users):
  files_attr = [{'Owner': 'Owner', 'Name': 'Name', 'URL': 'URL'}]
  titles = ['Owner', 'Name', 'URL'] 
  todrive = False
  i = 5 
  while i < len(argv):
    if argv[i].lower() == 'todrive':
      todrive = True
      i += 1
    else:
      print 'Error: %s is not a valid argument for "gam ... show filelist"'
      return 3
  for user in users:
    driveObj = buildGAPIServiceObject('drive', user)
    if user.find('@') == -1:
      print 'Error: got %s, expected a full email address' % user
      return 3
    sys.stderr.write('Getting files for %s...\n' % user)
    page_message = ' got %%%%total_items%%%% files for %s...\n' % user
    feed = callGAPIpages(service=driveObj.files(), function='list', items='items', page_message=page_message, q='"me" in owners', maxResults=1000, fields='items(title,alternateLink),nextPageToken')
    if type(feed) is int:
      continue
    for file in feed:
      a_file = {'Owner': user}
      try:
        a_file['Name'] = file['title']
      except KeyError:
        pass
      try:
        a_file['URL'] = file['alternateLink']
      except KeyError:
        pass
      files_attr.append(a_file)
  output_csv(files_attr, titles, '%s %s Drive Files' % (argv[1], argv[2]), todrive)

def createDriveFile(users):
  for user in users:
    filename = 'gpd-users.csv'
    driveObj = buildGAPIServiceObject('drive', user)
    #media_body = MediaFileUpload(filename, mimetype='text/plain', resumable=True)
    #result = drive.files().insert(convert=True, media_body=media_body, body={'mimeType': 'text/plain', 'title': filename}).execute()
    #for key in result.keys():
    #  print '%s: %s' % (key, result[key])
    #print ''
    result2 = callGAPI(service=driveObj.files(), function='patch', fileId='0B8aCWH-xLi2Nb05ZOHBMZzFHbTg', body={'title': 'new-title', 'writersCanShare': False})
    if type(result2) is int:
        continue
    for key in result2.keys():
      print '%s: %s' % (key, result2[key])

def showDriveFileInfo(users):
  for user in users:
    fileId = argv[5]
    driveObj = buildGAPIServiceObject('drive', user)
    feed = callGAPI(service=driveObj.files(), function='get', fileId=fileId)
    if type(feed) is int:
      continue
    for setting in feed.keys():
      if setting == u'kind':
        continue
      setting_type = str(type(feed[setting]))
      if setting_type == "<type 'list'>":
        print '%s:' % setting
        for settin in feed[setting]:
          if settin == u'kind':
            continue
          settin_type = str(type(settin))
          if settin_type == "<type 'dict'>":
            for setti in settin.keys():
              if setti == 'kind':
                continue
              print ' %s: %s' % (setti, settin[setti])
            print ''
      elif setting_type == "<type 'dict'>":
        print '%s:' % setting
        for settin in feed[setting].keys():
          if settin == u'kind':
            continue
          print ' %s: %s' % (settin, feed[setting][settin])
      else:
        print '%s: %s' % (setting, feed[setting])

def transferSecCals(users):
  target_user = argv[5]
  remove_source_user = True
  try:
    if argv[6].lower() == 'keepuser':
      remove_source_user = False
  except IndexError:
    target_cal = buildGAPIServiceObject('calendar', target_user)
  for user in users:
    source_cal = buildGAPIServiceObject('calendar', user)
    source_calendars = callGAPIpages(service=source_cal.calendarList(), function='list', minAccessRole='owner', items='items', showHidden=True, fields='items(id),nextPageToken')
    for source_cal in source_calendars:
      if source_cal['id'].find('@group.calendar.google.com') != -1:
        doCalendarAddACL(calendarId=source_cal['id'], act_as=user, role='owner', scope='user', entity=target_user)
        if remove_source_user:
          doCalendarAddACL(calendarId=source_cal['id'], act_as=target_user, role='none', scope='user', entity=user)

def transferDriveFiles(users):
  target_user = argv[5]
  remove_source_user = True
  try:
    if argv[6].lower() == 'keepuser':
      remove_source_user = False
  except IndexError:
    pass
  target_drive = buildGAPIServiceObject('drive', target_user)
  target_about = callGAPI(service=target_drive.about(), function='get', fields='quotaBytesTotal,quotaBytesUsed,rootFolderId')
  target_drive_free = int(target_about['quotaBytesTotal']) - int(target_about['quotaBytesUsed'])
  target_root = target_about['rootFolderId']
  for user in users:
    counter = 0
    source_drive = buildGAPIServiceObject('drive', user)
    source_about = callGAPI(service=source_drive.about(), function='get', fields='quotaBytesTotal,quotaBytesUsed,rootFolderId, permissionId')
    source_drive_size = int(source_about['quotaBytesUsed'])
    if target_drive_free < source_drive_size:
      print 'Error: Cowardly refusing to perform migration due to lack of target drive space. Source size: %smb Target Free: %smb' % (source_drive_size / 1024 / 1024, target_drive_free / 1024 / 1024)
      return 4
    print 'Source drive size: %smb  Target drive free: %smb' % (source_drive_size / 1024 / 1024, target_drive_free / 1024 / 1024)
    target_drive_free = target_drive_free - source_drive_size # prep target_drive_free for next user
    source_root = source_about['rootFolderId']
    source_permissionid = source_about['permissionId']
    print "Getting file list for source user: %s..." % user
    page_message = '  got %%total_items%% files\n'
    source_drive_files = callGAPIpages(service=source_drive.files(), function='list', items='items', page_message=page_message, q='\'me\' in owners and trashed = false', fields='items(id,parents,mimeType),nextPageToken')
    all_source_file_ids = []
    for source_drive_file in source_drive_files:
      all_source_file_ids.append(source_drive_file['id'])
    total_count = len(source_drive_files)
    print "Getting folder list for target user: %s..." % user
    page_message = '  got %%total_items%% folders\n'
    target_folders = callGAPIpages(service=target_drive.files(), function='list', items='items', page_message=page_message, q='\'me\' in owners and mimeType = \'application/vnd.google-apps.folder\'', fields='items(id,title),nextPageToken')
    got_top_folder = False
    all_target_folder_ids = []
    for target_folder in target_folders:
      all_target_folder_ids.append(target_folder['id'])
      if (not got_top_folder) and target_folder['title'] == '%s old files' % user:
        target_top_folder = target_folder['id']
        got_top_folder = True
    if not got_top_folder:
      create_folder = callGAPI(service=target_drive.files(), function='insert', body={'title': '%s old files' % user, 'mimeType': 'application/vnd.google-apps.folder'}, fields='id')
      target_top_folder = create_folder['id']
    folder_tree = []
    transferred_files = []
    while True: # we loop thru, skipping files until all of their parents are done
      skipped_files = False
      for drive_file in source_drive_files:
        file_id = drive_file['id']
        if file_id in transferred_files:
          continue
        source_parents = drive_file['parents']
        skip_file_for_now = False
        for source_parent in source_parents:
          if source_parent['id'] not in all_source_file_ids and source_parent['id'] not in all_target_folder_ids:
            continue  # means this parent isn't owned by source or target, shouldn't matter
          if source_parent['id'] not in transferred_files and source_parent['id'] != source_root:
            #print 'skipping %s' % file_id
            skipped_files = skip_file_for_now = True
            break
        if skip_file_for_now:
          continue
        else:
          transferred_files.append(drive_file['id'])
        counter += 1
        print 'Changing owner for file %s of %s' % (counter, total_count)
        body = {'role': 'owner', 'type': 'user', 'value': target_user}
        callGAPI(service=source_drive.permissions(), function='insert', fileId=file_id, sendNotificationEmails=False, body=body)
        target_parents = []
        for parent in source_parents:
          try:
            if parent['isRoot']:
              target_parents.append({'id': target_top_folder})
            else:
              target_parents.append({'id': parent['id']})
          except TypeError:
            pass
        callGAPI(service=target_drive.files(), function='patch', retry_reasons=['notFound'], fileId=file_id, body={'parents': target_parents})
        if remove_source_user:
          callGAPI(service=target_drive.permissions(), function='delete', fileId=file_id, permissionId=source_permissionid)
      if not skipped_files:
        break

def doImap(users):
  if argv[4].lower() == 'on':
    enable = True
  elif argv[4].lower() == 'off':
    enable = False
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    print "Setting IMAP Access to %s for %s (%s of %s)" % (str(enable), user+'@'+emailsettings.domain, i, count)
    i += 1
    try_count = 0
    callGData(service=emailsettings, function='UpdateImap', username=user, enable=enable)

def getImap(users):
  emailsettings = getEmailSettingsObject()
  i = 1
  count = len(users)
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain
    imapsettings = callGData(service=emailsettings, function='GetImap', username=user)
    if type(imapsettings) is int:
      continue
    try:
      print 'User %s  IMAP Enabled:%s (%s of %s)' % (user+'@'+emailsettings.domain, imapsettings['enable'], i, count)
    except TypeError:
      pass
    i += 1

def getProductAndSKU(sku):
  product = None
  if sku == 'apps':
    product = 'Google-Apps'
    sku = 'Google-Apps-For-Business'
  elif sku == 'apps-free':
    product = sku = 'Google-Apps'
  elif sku == 'coordinate':
    sku = product = 'Google-Coordinate'
  elif sku == 'vault':
    sku = product = 'Google-Vault'
  elif sku in ['drive-20gb', 'drive20gb', '20gb']:
    product = 'Google-Drive-storage'
    sku = 'Google-Drive-storage-20GB'
  elif sku in ['drive-50gb', 'drive50gb', '50gb']:
    product = 'Google-Drive-storage'
    sku = 'Google-Drive-storage-50GB'
  elif sku in ['drive-200gb', 'drive200gb', '200gb']:
    product = 'Google-Drive-storage'
    sku = 'Google-Drive-storage-200GB'
  elif sku in ['drive-400gb', 'drive400gb', '400gb']:
    product = 'Google-Drive-storage'
    sku = 'Google-Drive-storage-400GB'
  elif sku in ['drive-1tb', 'drive1tb', '1tb']:
    product = 'Google-Drive-storage'
    sku = 'Google-Drive-storage-1TB'
  elif sku in ['drive-2tb', 'drive2tb', '2tb']:
    product = 'Google-Drive-storage'
    sku = 'Google-Drive-storage-2TB'
  elif sku in ['drive-4tb', 'drive4tb', '4tb']:
    product = 'Google-Drive-storage'
    sku = 'Google-Drive-storage-4TB'
  elif sku in ['drive-4tb', 'drive8tb', '8tb']:
    product = 'Google-Drive-storage'
    sku = 'Google-Drive-storage-8TB'
  elif sku in ['drive-16tb', 'drive16tb', '16tb']:
    product = 'Google-Drive-storage'
    sku = 'Google-Drive-storage-16TB'
  return (product, sku)

def doLicense(users, operation):
  licensingObj = buildGAPIObject('licensing')
  i = 1
  count = len(users)
  sku = argv[5].lower()
  productId, skuId = getProductAndSKU(sku)
  for user in users:
    if user.find('@') == -1:
      user = '%s@%s' % (user, domain)
    if operation == 'delete':
      callGAPI(service=licensingObj.licenseAssignments(), function=operation, productId=productId, skuId=skuId, userId=user)
    elif operation == 'insert':
      callGAPI(service=licensingObj.licenseAssignments(), function=operation, productId=productId, skuId=skuId, body={'userId': user})
    elif operation == 'patch':
      callGAPI(service=licensingObj.licenseAssignments(), function=operation, productId=productId, skuId=skuId, userId=user, body={'skuId': skuId})

def doPop(users):
  if argv[4].lower() == 'on':
    enable = True
  elif argv[4].lower() == 'off':
    enable = False
  enable_for = 'ALL_MAIL'
  action = 'KEEP'
  i = 5
  while i < len(argv):
    if argv[i].lower() == 'for':
      if argv[i+1].lower() == 'allmail':
        enable_for = 'ALL_MAIL'
        i += 2
      elif argv[i+1].lower() == 'newmail':
        enable_for = 'MAIL_FROM_NOW_ON'
        i += 2
    elif argv[i].lower() == 'action':
      if argv[i+1].lower() == 'keep':
        action = 'KEEP'
        i += 2
      elif argv[i+1].lower() == 'archive':
        action = 'ARCHIVE'
        i += 2
      elif argv[i+1].lower() == 'delete':
        action = 'DELETE'
        i += 2
    elif argv[i].lower() == 'confirm':
      checkTOS = True
      i += 1
    else:
      showUsage()
      return 2
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    print "Setting POP Access to %s for %s (%s of %s)" % (str(enable), user+'@'+emailsettings.domain, i, count)
    i += 1
    callGData(service=emailsettings, function='UpdatePop', username=user, enable=enable, enable_for=enable_for, action=action)

def getPop(users):
  emailsettings = getEmailSettingsObject()
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain
    popsettings = callGData(service=emailsettings, function='GetPop', username=user)
    if type(popsettings) is int:
      continue
    try:
      print 'User %s  POP Enabled:%s  Action:%s' % (user+'@'+emailsettings.domain, popsettings['enable'], popsettings['action'])
    except TypeError:
      pass

def doSendAs(users):
  sendas = argv[4]
  sendasName = argv[5]
  make_default = reply_to = None
  i = 6
  while i < len(argv):
    if argv[i].lower() == 'default':
      make_default = True
      i += 1
    elif argv[i].lower() == 'replyto':
      reply_to = argv[i+1]
      i += 2
    else:
      showUsage()
      return 2
  emailsettings = getEmailSettingsObject()
  if sendas.find('@') < 0:
    sendas = sendas+'@'+domain
  count = len(users)
  i = 1
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    print "Allowing %s to send as %s (%s of %s)" % (user+'@'+emailsettings.domain, sendas, i, count)
    i += 1
    callGData(service=emailsettings, function='CreateSendAsAlias', username=user, name=sendasName, address=sendas, make_default=make_default, reply_to=reply_to)

def showSendAs(users):
  emailsettings = getEmailSettingsObject()
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain
    print '%s has the following send as aliases:' %  (user+'@'+emailsettings.domain)
    sendases = callGData(service=emailsettings, function='GetSendAsAlias', username=user)
    if type(sendases) is int:
      continue
    try:
      for sendas in sendases:
        if sendas['isDefault'] == 'true':
          default = 'yes'
        else:
          default = 'no'
        if sendas['replyTo']:
          replyto = ' Reply To:<'+sendas['replyTo']+'>'
        else:
          replyto = ''
        if sendas['verified'] == 'true':
          verified = 'yes'
        else:
          verified = 'no'
        print ' "%s" <%s>%s Default:%s Verified:%s' % (sendas['name'], sendas['address'], replyto, default, verified)
    except TypeError:
      pass
    print ''

def doLanguage(users):
  language = argv[4].lower()
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    print "Setting the language for %s to %s (%s of %s)" % (user+'@'+emailsettings.domain, language, i, count)
    i += 1
    callGData(service=emailsettings, function='UpdateLanguage', username=user, language=language)

def doUTF(users):
  if argv[4].lower() == 'on':
    SetUTF = True
  elif argv[4].lower() == 'off':
    SetUTF = False
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    print "Setting UTF-8 to %s for %s (%s of %s)" % (str(SetUTF), user+'@'+emailsettings.domain, i, count)
    i += 1
    callGData(service=emailsettings, function='UpdateGeneral', username=user, unicode=SetUTF)

def doPageSize(users):
  if argv[4] == '25' or argv[4] == '50' or argv[4] == '100':
    PageSize = argv[4]
  else:
    showUsage()
    return 2
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    print "Setting Page Size to %s for %s (%s of %s)" % (PageSize, user+'@'+emailsettings.domain, i, count)
    i += 1
    callGData(service=emailsettings, function='UpdateGeneral', username=user, page_size=PageSize)

def doShortCuts(users):
  if argv[4].lower() == 'on':
    SetShortCuts = True
  elif argv[4].lower() == 'off':
    SetShortCuts = False
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    print "Setting Keyboard Short Cuts to %s for %s (%s of %s)" % (str(SetShortCuts), user+'@'+emailsettings.domain, i, count)
    i += 1
    callGData(service=emailsettings, function='UpdateGeneral', username=user, shortcuts=SetShortCuts)

def doArrows(users):
  if argv[4].lower() == 'on':
    SetArrows = True
  elif argv[4].lower() == 'off':
    SetArrows = False
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    print "Setting Personal Indicator Arrows to %s for %s (%s of %s)" % (str(SetArrows), user+'@'+emailsettings.domain, i, count)
    i += 1
    callGData(service=emailsettings, function='UpdateGeneral', username=user, arrows=SetArrows)

def doSnippets(users):
  if argv[4].lower() == 'on':
    SetSnippets = True
  elif argv[4].lower() == 'off':
    SetSnippets = False
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    print "Setting Preview Snippets to %s for %s (%s of %s)" % (str(SetSnippets), user+'@'+emailsettings.domain, i, count)
    i += 1
    callGData(service=emailsettings, function='UpdateGeneral', username=user, snippets=SetSnippets)

def doLabel(users):
  label = argv[4]
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    print "Creating label %s for %s (%s of %s)" % (label, user+'@'+emailsettings.domain, i, count)
    i += 1
    callGData(service=emailsettings, function='CreateLabel', username=user, label=label)

def doDeleteLabel(users):
  label = argv[5]
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain
    if label == '--ALL_LABELS--':
      print 'Getting all labels...'
      labels = callGData(service=emailsettings, function='GetLabels', username=user)
      count = len(labels)
      y = 0
      for del_label in labels:
        y += 1
        print 'Deleting "%s" (%s/%s)' % (del_label['label'], y, count)
        try:
          callGData(service=emailsettings, function='DeleteLabel', throw_errors=[1000,], username=user, label=del_label['label'])
        except gdata.apps.service.AppsForYourDomainException:
          continue
    elif label[:6].lower() == 'regex:':
      regex = label[6:]
      p = re.compile(regex)
      print 'Getting all labels...'
      labels = callGData(service=emailsettings, function='GetLabels', username=user)
      count = len(labels)
      y = 0
      for del_label in labels:
        y += 1
        if p.match(del_label['label']):
          print 'Deleting "%s" (%s/%s)' % (del_label['label'], y, count)
          try:
            callGData(service=emailsettings, function='DeleteLabel', throw_errors=[1000,], username=user, label=del_label['label'])
          except gdata.apps.service.AppsForYourDomainException:
            continue
        else:
          print 'Skipping "%s" (%s/%s)' % (del_label['label'], y, count)
    else:
      print "Deleting label %s for %s (%s of %s)" % (label, user+'@'+emailsettings.domain, i, count)
      callGData(service=emailsettings, function='DeleteLabel', username=user, label=label)
    i += 1

def showLabels(users):
  emailsettings = getEmailSettingsObject()
  csv_format = False
  try:
    if argv[5].lower() == 'csv':
      print 'user,numLabels'
      csv_format = True
  except IndexError:
    pass
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain
    if not csv_format:
      print '%s has the following labels:' %  (user+'@'+emailsettings.domain)
    labels = callGData(service=emailsettings, function='GetLabels', username=user)
    if type(labels) is int:
      continue
    try:
      if csv_format:
        print '%s,%s' % (user, len(labels))
        continue
      else:
        for label in labels:
          print ' %s  Unread:%s  Visibility:%s' % (label['label'], label['unreadCount'], label['visibility'])
        print ''
    except TypeError:
      pass

def doFilter(users):
  i = 4 # filter arguments start here
  from_ = to = subject = has_the_word = does_not_have_the_word = has_attachment = label = should_mark_as_read = should_archive = should_star = forward_to = should_trash = should_not_spam = None
  haveCondition = False
  while argv[i].lower() == 'from' or argv[i].lower() == 'to' or argv[i].lower() == 'subject' or argv[i].lower() == 'haswords' or argv[i].lower() == 'nowords' or argv[i].lower() == 'musthaveattachment':
    if argv[i].lower() == 'from':
      from_ = argv[i+1]
      i += 2
      haveCondition = True
    elif argv[i].lower() == 'to':
      to = argv[i+1]
      i += 2
      haveCondition = True
    elif argv[i].lower() == 'subject':
      subject = argv[i+1]
      i += 2
      haveCondition = True
    elif argv[i].lower() == 'haswords':
      has_the_word = argv[i+1]
      i += 2
      haveCondition = True
    elif argv[i].lower() == 'nowords':
      does_not_have_the_word = argv[i+1]
      i += 2
      haveCondition = True
    elif argv[i].lower() == 'musthaveattachment':
      has_attachment = True
      i += 1
      haveCondition = True
  if not haveCondition:
    showUsage()
    return 2
  haveAction = False
  while i < len(argv):
    if argv[i].lower() == 'label':
      label = argv[i+1]
      i += 2
      haveAction = True
    elif argv[i].lower() == 'markread':
      should_mark_as_read = True
      i += 1
      haveAction = True
    elif argv[i].lower() == 'archive':
      should_archive = True
      i += 1
      haveAction = True
    elif argv[i].lower() == 'star':
      should_star = True
      i += 1
      haveAction = True
    elif argv[i].lower() == 'forward':
      forward_to = argv[i+1]
      i += 2
      haveAction = True
    elif argv[i].lower() == 'trash':
      should_trash = True
      i += 1
      haveAction = True
    elif argv[i].lower() == 'neverspam':
      should_not_spam = True
      i += 1
      haveAction = True
    else:
      showUsage()
      return 2
  if not haveAction:
    showUsage()
    return 2
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    print "Creating filter for %s (%s of %s)" % (user+'@'+emailsettings.domain, i, count)
    i += 1
    callGData(service=emailsettings, function='CreateFilter', username=user, from_=from_, to=to, subject=subject, has_the_word=has_the_word, does_not_have_the_word=does_not_have_the_word, has_attachment=has_attachment, label=label, should_mark_as_read=should_mark_as_read, should_archive=should_archive, should_star=should_star, forward_to=forward_to, should_trash=should_trash, should_not_spam=should_not_spam)

def doForward(users):
  action = forward_to = None
  gotAction = gotForward = False
  if argv[4] == 'on':
    enable = True
  elif argv[4] == 'off':
    enable = False
  else:
    showUsage()
    return 2
  i = 5
  while i < len(argv):
    if argv[i].lower() == 'keep' or argv[i].lower() == 'archive' or argv[i].lower() == 'delete':
      action = argv[i].upper()
      i += 1
      gotAction = True
    elif argv[i].lower() == 'confirm':
      checkTOS = True
      i += 1
    elif argv[i].find('@') != -1:
      forward_to = argv[i]
      gotForward = True
      i += 1
    else:
      showUsage()
      return 2
  if enable and (not gotAction or not gotForward):
    showUsage()
    return 
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    print "Turning forward %s for %s, emails will be %s (%s of %s)" % (argv[4], user+'@'+emailsettings.domain, action, i, count)
    i += 1
    callGData(service=emailsettings, function='UpdateForwarding', username=user, enable=enable, action=action, forward_to=forward_to)

def getForward(users):
  emailsettings = getEmailSettingsObject()
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain
    forward = callGData(service=emailsettings, function='GetForward', username=user)
    if type(forward) is int:
        continue
    try:
      print "User %s:  Forward To:%s  Enabled:%s  Action:%s" % (user+'@'+emailsettings.domain, forward['forwardTo'], forward['enable'], forward['action'])
    except TypeError:
      pass

def doSignature(users):
  import cgi
  if argv[4].lower() == 'file':
    fp = open(argv[5], 'rb')
    signature = cgi.escape(fp.read().replace('\\n', '&#xA;').replace('"', "'"))
    fp.close()
  else:
    signature = cgi.escape(argv[4]).replace('\\n', '&#xA;').replace('"', "'")
  xmlsig = '''<?xml version="1.0" encoding="utf-8"?>
<atom:entry xmlns:atom="http://www.w3.org/2005/Atom" xmlns:apps="http://schemas.google.com/apps/2006">
    <apps:property name="signature" value="%s" />
</atom:entry>''' % signature
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    print "Setting Signature for %s (%s of %s)" % (user+'@'+emailsettings.domain, i, count)
    uri = 'https://apps-apis.google.com/a/feeds/emailsettings/2.0/%s/%s/signature' % (emailsettings.domain, user)
    i += 1
    callGData(service=emailsettings, function='Put', data=xmlsig, uri=uri)

def getSignature(users):
  emailsettings = getEmailSettingsObject()
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain
    signature = callGData(service=emailsettings, function='GetSignature', username=user)
    if type(signature) is int:
      continue
    try:
      sys.stderr.write("User %s signature:\n  " % (user+'@'+emailsettings.domain))
      print " %s" % signature['signature']
    except TypeError:
      pass

def doWebClips(users):
  if argv[4].lower() == 'on':
    enable = True
  elif argv[4].lower() == 'off':
    enable = False
  else:
    showUsage()
    return 2
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    print "Turning Web Clips %s for %s (%s of %s)" % (argv[4], user+'@'+emailsettings.domain, i, count)
    i += 1
    callGData(service=emailsettings, function='UpdateWebClipSettings', username=user, enable=enable)

def doVacation(users):
  import cgi
  subject = message = ''
  if argv[4] == 'on':
    enable = 'true'
  elif argv[4] == 'off':
    enable = 'false'
  else:
    showUsage()
    return 2
  contacts_only = domain_only = 'false'
  start_date = end_date = None
  i = 5
  while i < len(argv):
    if argv[i].lower() == 'subject':
      subject = argv[i+1]
      i += 2
    elif argv[i].lower() == 'message':
      message = argv[i+1]
      i += 2
    elif argv[i].lower() == 'contactsonly':
      contacts_only = 'true'
      i += 1
    elif argv[i].lower() == 'domainonly':
      domain_only = 'true'
      i += 1
    elif argv[i].lower() == 'startdate':
      start_date = argv[i+1]
      i += 2
    elif argv[i].lower() == 'enddate':
      end_date = argv[i+1]
      i += 2
    elif argv[i].lower() == 'file':
      fp = open(argv[i+1], 'rb')
      message = fp.read()
      fp.close()
      i += 2
    else:
      showUsage()
      return 2
  i = 1
  count = len(users)
  emailsettings = getEmailSettingsObject()
  message = cgi.escape(message).replace('\\n', '&#xA;').replace('"', "'")
  vacxml = '''<?xml version="1.0" encoding="utf-8"?>
<atom:entry xmlns:atom="http://www.w3.org/2005/Atom" xmlns:apps="http://schemas.google.com/apps/2006">
    <apps:property name="enable" value="%s" />''' % enable
  vacxml += '''<apps:property name="subject" value="%s" />
    <apps:property name="message" value="%s" />
    <apps:property name="contactsOnly" value="%s" />
    <apps:property name="domainOnly" value="%s" />''' % (subject, message, contacts_only, domain_only)
  if start_date != None:
    vacxml += '''<apps:property name="startDate" value="%s" />''' % start_date
  if end_date != None:
    vacxml += '''<apps:property name="endDate" value="%s" />''' % end_date
  vacxml += '</atom:entry>'
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    print "Setting Vacation for %s (%s of %s)" % (user+'@'+emailsettings.domain, i, count)
    uri = 'https://apps-apis.google.com/a/feeds/emailsettings/2.0/%s/%s/vacation' % (emailsettings.domain, user)
    i += 1
    callGData(service=emailsettings, function='Put', data=vacxml, uri=uri)

def getVacation(users):
  emailsettings = getEmailSettingsObject()
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain
    vacationsettings = callGData(service=emailsettings, function='GetVacation', username=user)
    if type(vacationsettings) is int:
      continue
    try:
      print '''User %s
 Enabled: %s
 Contacts Only: %s
 Domain Only: %s
 Subject: %s
 Message: %s
 Start Date: %s
 End Date: %s
''' % (user+'@'+emailsettings.domain, vacationsettings['enable'], vacationsettings['contactsOnly'], vacationsettings['domainOnly'], vacationsettings['subject'], vacationsettings['message'], vacationsettings['startDate'], vacationsettings['endDate'])
    except TypeError:
      pass

def createUserCallBack(request_id, response, exception):
  if exception is not None:
    print exception
  else:
    print 'Created user %s' % response['primaryEmail']

def doCreateUser():
  directoryObj = buildGAPIObject('directory')
  body = dict()
  body['name'] = dict()
  body['primaryEmail'] = argv[3]
  if body['primaryEmail'].find('@') == -1:
    body['primaryEmail'] = '%s@%s' % (body['primaryEmail'], domain)
  gotFirstName = gotLastName = False
  need_to_hash_password = need_password = True
  i = 4
  while i < len(argv):
    if argv[i].lower() == 'firstname':
      body['name']['givenName'] = argv[i+1]
      gotFirstName = True
      i += 2
    elif argv[i].lower() == 'lastname':
      body['name']['familyName'] = argv[i+1]
      gotLastName = True
      i += 2
    elif argv[i].lower() == 'password':
      body['password'] = argv[i+1]
      need_password = False
      i += 2
    elif argv[i].lower() == 'suspended':
      if argv[i+1].lower() == 'on':
        body['suspended'] = True
      elif argv[i+1].lower() == 'off':
        body['suspended'] = False
      else:
        print 'Error: suspended should be on or off, not %s' % argv[i+1]
        return 5
      i += 2
    elif argv[i].lower() == 'gal':
      if argv[i+1].lower() in ['on', 'true']:
        body['includeInGlobalAddressList'] = True
      elif argv[i+1].lower() in ['off', 'false']:
        body['includeInGlobalAddressList'] = False
      else:
        print 'Error: gal should be on or off, not %s' % argv[i+1]
        return 5
      i += 2
    elif argv[i].lower() == 'sha' or argv[i].lower() == 'sha1' or argv[i].lower() == 'sha-1':
      body['hashFunction'] = 'SHA-1'
      need_to_hash_password = False
      i += 1
    elif argv[i].lower() == 'md5':
      body['hashFunction'] = 'MD5'
      need_to_hash_password = False
      i += 1
    elif argv[i].lower() == 'crypt':
      body['hashFunction'] = 'crypt'
      need_to_hash_password = False
      i += 1
    elif argv[i].lower() == 'nohash':
      need_to_hash_password = False
      i += 1
    elif argv[i].lower() == 'changepassword':
      if argv[i+1] == 'on':
        body['changePasswordAtNextLogin'] = True
      elif argv[i+1] == 'off':
        body['changePasswordAtNextLogin'] = False
      else:
        print 'Error: changepassword should be on or off, not %s' % argv[i+1]
        return 5
      i += 2
    elif argv[i].lower() == 'ipwhitelisted':
      if argv[i+1] == 'on':
        body['ipWhitelisted'] = True
      elif argv[i+1] == 'off':
        body['ipWhitelisted'] = False
      else:
        print 'Error: ipwhitelisted should be on or off, not %s' % argv[i+1]
      i += 2
    elif argv[i].lower() == 'agreedtoterms':
      if argv[i+1] == 'on':
        body['agreedToTerms'] = True
      elif argv[i+1] == 'off':
        body['agreedToTerms'] = False
      else:
        print 'Error: agreedtoterms should be on or off, not %s' % argv[i+1]
        return 5
      i += 2
    elif argv[i].lower() == 'org' or argv[i].lower() == 'ou':
      org = argv[i+1]
      if org[1] != '/':
        org = '/%s' % org
      body['orgUnitPath'] = org
      i += 2
    elif argv[i].lower() == 'im':
      im = dict()
      i += 1
      if argv[i].lower() != 'type':
        print 'Error: wrong format for account im details. Expected type got %s' % argv[i]
        return 6
      i += 1
      im['type'] = argv[i].lower()
      if im['type'] not in ['custom', 'home', 'other', 'work']:
        print 'Error: type should be custom, home, other or work. Got %s' % im['type']
        return 7
      if im['type'] == 'custom':
        i += 1
        im['customType'] = argv[i]
      i += 1
      if argv[i].lower() != 'protocol':
        print 'Error: wrong format for account details. Expected protocol got %s' % argv[i]
        return 8
      i += 1
      im['protocol'] = argv[i].lower()
      if im['protocol'] not in ['custom_protocol', 'aim', 'gtalk', 'icq', 'jabber', 'msn', 'net_meeting', 'qq', 'skype', 'yahoo']:
        print 'Error: protocol should be custom_protocol, aim, gtalk, icq, jabber, msn, net_meeting, qq, skype or yahoo. Got %s' % im['protocol']
      if im['protocol'] == 'custom_protocol':
        i += 1
        im['customProtocol'] = argv[i]
      i += 1
      if argv[i].lower() == 'primary':
        im['primary'] = True
        i += 1
      im['im'] = argv[i]
      try:
        body['ims'].append(im)
      except KeyError:
        body['ims'] = [im,]
      i += 1
    elif argv[i].lower() == 'address':
      address = dict()
      i += 1
      if argv[i].lower() != 'type':
        print 'Error: wrong format for account address details. Expected type got %s' % argv[i]
        return 9
      i += 1
      address['type'] = argv[i].lower()
      if address['type'] not in ['custom', 'home', 'other', 'work']:
        print 'Error: wrong type should be custom, home, other or work. Got %s' % address['type']
        return 10
      if address['type'] == 'custom':
        i += 1
        address['customType'] = argv[i]
      i += 1
      if argv[i].lower() == 'unstructured':
        i += 1
        address['sourceIsStructured'] = False
        address['formatted'] = argv[i]
        i += 1
      while True:
        argument = argv[i].lower()
        if argument == 'pobox':
          address['poBox'] = argv[i+1]
          i += 2
        elif argument == 'extendedaddress':
          address['extendedAddress'] = argv[i+1]
          i += 2
        elif argument == 'streetaddress':
          address['streetAddress'] = argv[i+1]
          i += 2
        elif argument == 'locality':
          address['locality'] = argv[i+1]
          i += 2
        elif argument == 'region':
          address['region'] = argv[i+1]
          i += 2
        elif argument == 'postalcode':
          address['postalCode'] = argv[i+1]
          i += 2
        elif argument == 'country':
          address['country'] = argv[i+1]
          i += 2
        elif argument == 'countrycode':
          address['countryCode'] = argv[i+1]
          i += 2
        elif argument == 'notprimary':
          i += 1
          break
        elif argument == 'primary':
          address['primary'] = True
          i += 1
          break
      try:
        body['addresses'].append(address)
      except KeyError:
        body['addresses'] = [address,]
    elif argv[i].lower() == 'organization':
      organization = dict()
      i += 1
      while True:
        argument = argv[i].lower()
        if argument == 'name':
          organization['name'] = argv[i+1]
          i += 2
        elif argument == 'title':
          organization['title'] = argv[i+1]
          i += 2
        elif argument == 'customtype':
          organization['customType'] = argv[i+1]
          i += 2
        elif argument == 'type':
          organization['type'] = argv[i+1].lower()
          if organization['type'] not in ['domain_only', 'school', 'unknown', 'work']:
            print 'Error: organization type must be domain_only, school, unknown or work. Got %s' % organization['type']
            return 11
          i += 2
        elif argument == 'department':
          organization['department'] = argv[i+1]
          i += 2
        elif argument == 'symbol':
          organization['symbol'] = argv[i+1]
          i += 2
        elif argument == 'costcenter':
          organization['costCenter'] = argv[i+1]
          i += 2
        elif argument == 'location':
          organization['location'] = argv[i+1]
          i += 2
        elif argument == 'description':
          organization['description'] = argv[i+1]
          i += 2
        elif argument == 'domain':
          organization['domain'] = argv[i+1]
          i += 2
        elif argument == 'notprimary':
          i += 1
          break
        elif argument == 'primary':
          organization['primary'] = True
          i += 1
          break
      try:
        body['organizations'].append(organization)
      except KeyError:
        body['organizations'] = [organization,]
    elif argv[i].lower() == 'phone':
      phone = dict()
      i += 1
      while True:
        argument = argv[i].lower()
        if argument == 'value':
          phone['value'] = argv[i+1]
          i += 2
        elif argument == 'type':
          phone['type'] = argv[i+1].lower()
          if phone['type'] not in ['assistant', 'callback', 'car', 'company_main', 'custom', 'grand_central', 'home', 'home_fax', 'isdn', 'main', 'mobile', 'other', 'other_fax', 'pager', 'radio', 'telex', 'tty_tdd', 'work', 'work_fax', 'work_mobile', 'work_pager']:
            print 'Error: phone type must be assistant, callback, car, company_main, custom, grand_central, home, home_fax, isdn, main, mobile, other, other_fax, pager, radio, telex, tty_tdd, work, work_fax, work_mobile, work_pager. Got %s' % phone['type']
            return 12
          i += 2
          if phone['type'] == 'custom':
            phone['customType'] = argv[i]
            i += 1
        elif argument == 'notprimary':
          i += 1
          break
        elif argument == 'primary':
          phone['primary'] = True
          i += 1
          break
      try:
        body['phones'].append(phone)
      except KeyError:
        body['phones'] = [phone,]
    elif argv[i].lower() == 'relation':
      do_update_user = True
      relation = dict()
      i += 1
      relation['type'] = argv[i]
      if relation['type'].lower() not in ['mother', 'father', 'sister', 'brother', 'manager', 'assistant', 'partner']:
        relation['type'] = 'custom'
        relation['customType'] = argv[i]
      i += 1
      relation['value'] = argv[i]
      try:
        body['relations'].append(relation)
      except KeyError:
        body['relations'] = [relation,]
      i += 1
    elif argv[i].lower() == 'externalid':
      do_update_user = True
      externalid = dict()
      i += 1
      externalid['type'] = argv[i]
      if externalid['type'].lower() not in []:
        externalid['type'] = 'custom'
        externalid['customType'] = argv[i]
      i += 1
      externalid['value'] = argv[i]
      try:
        body['externalIds'].append(externalid)
      except KeyError:
        body['externalIds'] = [externalid,]
      i += 1
    else:
      showUsage()
      return 2
  if not gotFirstName:
    body['name']['givenName'] = 'Unknown'
  if not gotLastName:
    body['name']['familyName'] = 'Unknown'
  if need_password:
    body['password'] = ''.join(random.sample('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~`!@#$%^&*()-=_+:;"\'{}[]\\|', 25))
  if need_to_hash_password:
    newhash = hashlib.sha1()
    newhash.update(body['password'])
    body['password'] = newhash.hexdigest()
    body['hashFunction'] = 'SHA-1'
  print "Creating account for %s" % body['primaryEmail']
  callGAPIBatch(service=directoryObj.users(), function='insert', callback=createUserCallBack, body=body, fields='primaryEmail')

def create_group_callback(request_id, response, exception):
  if exception is not None:
    print exception
  else:
    print response

def doCreateGroup():
  directoryObj = buildGAPIObject('directory')
  body = dict()
  body['email'] = argv[3]
  if body['email'].find('@') == -1:
    body['email'] = '%s@%s' % (body['email'], domain)
  body['name'] = body['email']
  i = 4
  while i < len(argv):
    if argv[i].lower() == 'name':
      body['name'] = argv[i+1]
      i += 2
    elif argv[i].lower() == 'description':
      body['description'] = argv[i+1]
      i += 2
    else:
      print 'Error: %s is not a valid argument for "gam create group..."' % argv[i]
      return
  callGAPIBatch(service=directoryObj.groups(), function='insert', callback=create_group_callback, body=body)

def generic_callback(request_id, response, exception):
  if exception is not None:
    try:
      error = json.loads(exception.content)
    except ValueError:
      sys.stderr.write(exception)
    http_status = error['error']['code']
    message = error['error']['errors'][0]['message']
    try:
      reason = error['error']['errors'][0]['reason']
    except KeyError:
      reason = http_status
    sys.stderr.write('Error %s: %s - %s\n\n' % (http_status, message, reason))

def doCreateAlias():
  directoryObj = buildGAPIObject('directory')
  body = dict()
  body['alias'] = argv[3]
  if body['alias'].find('@') == -1:
    body['alias'] = '%s@%s' % (body['alias'], domain)
  target_type = argv[4].lower()
  if target_type not in ['user', 'group']:
    print 'Error: type of target should be user or group. Got %s' % target_type
    return 3
  targetKey = argv[5]
  if targetKey.find('@') == -1:
    targetKey = '%s@%s' % (targetKey, domain)
  print 'Creating alias %s for %s %s' % (body['alias'], target_type, targetKey)
  if target_type == 'user':
    callGAPIBatch(service=directoryObj.users().aliases(), function='insert', callback=generic_callback, userKey=targetKey, body=body)
  elif target_type == 'group':
    callGAPIBatch(service=directoryObj.groups().aliases(), function='insert', callback=generic_callback, groupKey=targetKey, body=body)

def doCreateOrg():
  directoryObj = buildGAPIObject('directory')
  body = dict()
  body['name'] = argv[3]
  if body['name'][0] == '/':
    body['name'] = body['name'][1:]
  i = 4
  body['parentOrgUnitPath'] = '/'
  while i < len(argv):
    if argv[i].lower() == 'description':
      body['description'] = argv[i+1]
      i += 2
    elif argv[i].lower() == 'parent':
      body['parentOrgUnitPath'] = argv[i+1]
      i += 2
    elif argv[i].lower() == 'noinherit':
      body['blockInheritance'] = True
      i += 1
  callGAPIBatch(service=directoryObj.orgunits(), function='insert', callback=generic_callback, customerId=customerId, body=body)

def doCreateResource():
  id = argv[3]
  common_name = argv[4]
  description = None
  type = None
  i = 5
  while i < len(argv):
    if argv[i].lower() == 'description':
      description = argv[i+1]
      i += 2
    elif argv[i].lower() == 'type':
      type = argv[i+1]
      i += 2
  rescal = getResCalObject()
  callGData(service=rescal, function='CreateResourceCalendar', id=id, common_name=common_name, description=description, type=type)

def process_update_users(request_id, response, exception):
  if exception is not None:
    print exception
  else:
    print 'Updated user %s' % response['primaryEmail']

def doUpdateUser(users):
  directoryObj = buildGAPIObject('directory')
  body = dict()
  gotPassword = isMD5 = isSHA1 = isCrypt = False
  is_admin = nohash = None
  if argv[1].lower() == 'update':
    i = 4
  else:
    i = 5
  do_update_user = False
  do_admin_user = False
  while i < len(argv):
    if argv[i].lower() == 'firstname':
      do_update_user = True
      try:
        pointless = body['name']
      except KeyError:
        body['name'] = dict()
      body['name']['givenName'] = argv[i+1]
      i += 2
    elif argv[i].lower() == 'lastname':
      do_update_user = True
      try:
        pointless = body['name']
      except KeyError:
        body['name'] = dict()
      body['name']['familyName'] = argv[i+1]
      i += 2
    elif argv[i].lower() in ['username', 'email']:
      do_update_user = True
      body['primaryEmail'] = argv[i+1]
      if body['primaryEmail'].find('@') == -1:
        body['primaryEmail'] = '%s@%s' % (body['primaryEmail'], domain)
      i += 2
    elif argv[i].lower() == 'password':
      do_update_user = True
      body['password'] = argv[i+1]
      i += 2
      gotPassword = True
    elif argv[i].lower() == 'admin':
      do_admin_user = True
      if argv[i+1].lower() == 'on':
        is_admin = True
      elif argv[i+1].lower() == 'off':
        is_admin = False
      i += 2
    elif argv[i].lower() == 'suspended':
      do_update_user = True
      if argv[i+1].lower() == 'on':
        body['suspended'] = 'true'
      elif argv[i+1].lower() == 'off':
        body['suspended'] = 'false'
      i += 2
    elif argv[i].lower() == 'gal':
      do_update_user = True
      if argv[i+1].lower() == 'on':
        body['includeInGlobalAddressList'] = True
      elif argv[i+1].lower() == 'off':
        body['includeInGlobalAddressList'] = False
      else:
        print 'Error: gal should be on or off, not %s' % argv[i+1]
        return 5
      i += 2
    elif argv[i].lower() == 'ipwhitelisted':
      do_update_user = True
      if argv[i+1].lower() == 'on':
        body['ipWhitelisted'] = 'true'
      elif argv[i+1].lower() == 'off':
        body['ipWhitelisted'] = 'false'
      i += 2
    elif argv[i].lower() in ['sha', 'sha1', 'sha-1']:
      do_update_user = True
      body['hashFunction'] = 'SHA-1'
      i += 1
      isSHA1 = True
    elif argv[i].lower() == 'md5':
      do_update_user = True
      body['hashFunction'] = 'MD5'
      i += 1
      isMD5 = True
    elif argv[i].lower() == 'crypt':
      do_update_user = True
      body['hashFunction'] = 'crypt'
      i += 1
      isCrypt = True
    elif argv[i].lower() == 'nohash':
      nohash = True
      i += 1
    elif argv[i].lower() == 'changepassword':
      do_update_user = True
      if argv[i+1].lower() == 'on':
        body['changePasswordAtNextLogin'] = 'true'
      elif argv[i+1].lower() == 'off':
        body['changePasswordAtNextLogin'] = 'false'
      i += 2
    elif argv[i].lower() == 'org' or argv[i].lower() == 'ou':
      do_update_user = True
      body['orgUnitPath'] = argv[i+1]
      if body['orgUnitPath'][0] != '/':
        body['orgUnitPath'] = '/'+body['orgUnitPath']
      i += 2
    elif argv[i].lower() == 'agreedtoterms':
      do_update_user = True
      if argv[i+1].lower() == 'on':
        body['agreedToTerms'] = 'true'
      elif argv[i+1].lower() == 'off':
        body['agreedToTerms'] = 'false'
      i += 2
    elif argv[i].lower() == 'customerid':
      do_update_user = True
      body['customerId'] = argv[i+1]
      i += 2
    elif argv[i].lower() == 'im':
      do_update_user = True
      im = dict()
      i += 1
      if argv[i].lower() != 'type':
        print 'Error: wrong format for account im details. Expected type got %s' % argv[i]
        return 6
      i += 1
      im['type'] = argv[i].lower()
      if im['type'] not in ['custom', 'home', 'other', 'work']:
        print 'Error: type should be custom, home, other or work. Got %s' % im['type']
        return 7
      if im['type'] == 'custom':
        i += 1
        im['customType'] = argv[i]
      i += 1
      if argv[i].lower() != 'protocol':
        print 'Error: wrong format for account details. Expected protocol got %s' % argv[i]
        return 8
      i += 1
      im['protocol'] = argv[i].lower()
      if im['protocol'] not in ['custom_protocol', 'aim', 'gtalk', 'icq', 'jabber', 'msn', 'net_meeting', 'qq', 'skype', 'yahoo']:
        print 'Error: protocol should be custom_protocol, aim, gtalk, icq, jabber, msn, net_meeting, qq, skype or yahoo. Got %s' % im['protocol']
      if im['protocol'] == 'custom_protocol':
        i += 1
        im['customProtocol'] = argv[i]
      i += 1
      if argv[i].lower() == 'primary':
          im['primary'] = True
          i += 1
      im['im'] = argv[i]
      i += 1
      try:
        body['ims'].append(im)
      except KeyError:
        body['ims'] = [im,]
    elif argv[i].lower() == 'address':
      do_update_user = True
      address = dict()
      i += 1
      if argv[i].lower() != 'type':
        print 'Error: wrong format for account address details. Expected type got %s' % argv[i]
        return 9
      i += 1
      address['type'] = argv[i].lower()
      if address['type'] not in ['custom', 'home', 'other', 'work']:
        print 'Error: wrong type should be custom, home, other or work. Got %s' % address['type']
        return 10
      if address['type'] == 'custom':
        i += 1
        address['customType'] = argv[i]
      i += 1
      if argv[i].lower() == 'unstructured':
        i += 1
        address['sourceIsStructured'] = False
        address['formatted'] = argv[i]
        i += 1
      while True:
        argument = argv[i].lower()
        if argument == 'pobox':
          address['poBox'] = argv[i+1]
          i += 2
        elif argument == 'extendedaddress':
          address['extendedAddress'] = argv[i+1]
          i += 2
        elif argument == 'streetaddress':
          address['streetAddress'] = argv[i+1]
          i += 2
        elif argument == 'locality':
          address['locality'] = argv[i+1]
          i += 2
        elif argument == 'region':
          address['region'] = argv[i+1]
          i += 2
        elif argument == 'postalcode':
          address['postalCode'] = argv[i+1]
          i += 2
        elif argument == 'country':
          address['country'] = argv[i+1]
          i += 2
        elif argument == 'countrycode':
          address['countryCode'] = argv[i+1]
          i += 2
        elif argument == 'notprimary':
          i += 1
          break
        elif argument == 'primary':
          address['primary'] = True
          i += 1
          break
      try:
        body['addresses'].append(address)
      except KeyError:
        body['addresses'] = [address,]
    elif argv[i].lower() == 'organization':
      do_update_user = True
      organization = dict()
      i += 1
      while True:
        argument = argv[i].lower()
        if argument == 'name':
          organization['name'] = argv[i+1]
          i += 2
        elif argument == 'title':
          organization['title'] = argv[i+1]
          i += 2
        elif argument == 'customtype':
          organization['customType'] = argv[i+1]
          i += 2
        elif argument == 'type':
          organization['type'] = argv[i+1].lower()
          if organization['type'] not in ['domain_only', 'school', 'unknown', 'work']:
            print 'Error: organization type must be domain_only, school, unknown or work. Got %s' % organization['type']
            return 11
          i += 2
        elif argument == 'department':
          organization['department'] = argv[i+1]
          i += 2
        elif argument == 'symbol':
          organization['symbol'] = argv[i+1]
          i += 2
        elif argument == 'costcenter':
          organization['costCenter'] = argv[i+1]
          i += 2
        elif argument == 'location':
          organization['location'] = argv[i+1]
          i += 2
        elif argument == 'description':
          organization['description'] = argv[i+1]
          i += 2
        elif argument == 'domain':
          organization['domain'] = argv[i+1]
          i += 2
        elif argument == 'notprimary':
          i += 1
          break
        elif argument == 'primary':
          organization['primary'] = True
          i += 1
          break
      try:
        body['organizations'].append(organization)
      except KeyError:
        body['organizations'] = [organization,]
    elif argv[i].lower() == 'phone':
      do_update_user = True
      phone = dict()
      i += 1
      while True:
        argument = argv[i].lower()
        if argument == 'value':
          phone['value'] = argv[i+1]
          i += 2
        elif argument == 'type':
          phone['type'] = argv[i+1].lower()
          if phone['type'] not in ['assistant', 'callback', 'car', 'company_main', 'custom', 'grand_central', 'home', 'home_fax', 'isdn', 'main', 'mobile', 'other', 'other_fax', 'pager', 'radio', 'telex', 'tty_tdd', 'work', 'work_fax', 'work_mobile', 'work_pager']:
            print 'Error: phone type must be assistant, callback, car, company_main, custom, grand_central, home, home_fax, isdn, main, mobile, other, other_fax, pager, radio, telex, tty_tdd, work, work_fax, work_mobile, work_pager. Got %s' % phone['type']
            return 12
          i += 2
          if phone['type'] == 'custom':
            phone['customType'] = argv[i]
            i += 1
        elif argument == 'notprimary':
          i += 1
          break
        elif argument == 'primary':
          phone['primary'] = True
          i += 1
          break
      try:
        body['phones'].append(phone)
      except KeyError:
        body['phones'] = [phone,]
    elif argv[i].lower() == 'relation':
      do_update_user = True
      relation = dict()
      i += 1
      relation['type'] = argv[i]
      if relation['type'].lower() not in ['mother', 'father', 'sister', 'brother', 'manager', 'assistant', 'partner']:
        relation['type'] = 'custom'
        relation['customType'] = argv[i]
      i += 1
      relation['value'] = argv[i]
      try:
        body['relations'].append(relation)
      except KeyError:
        body['relations'] = [relation,]
      i += 1
    elif argv[i].lower() == 'externalid':
      do_update_user = True
      externalid = dict()
      i += 1
      externalid['type'] = argv[i]
      if externalid['type'].lower() not in []:
        externalid['type'] = 'custom'
        externalid['customType'] = argv[i]
      i += 1
      externalid['value'] = argv[i]
      try:
        body['externalIds'].append(externalid)
      except KeyError:
        body['externalIds'] = [externalid,]
      i += 1
    else:
      showUsage()
      print ''
      print 'Error: didn\'t expect %s command at position %s' % (argv[i], i)
      print body
      return 2
  if gotPassword and not (isSHA1 or isMD5 or isCrypt or nohash):
    newhash = hashlib.sha1()
    newhash.update(body['password'])
    body['password'] = newhash.hexdigest()
    body['hashFunction'] = 'SHA-1'
  for user in users:
    if user[:4].lower() == 'uid:':
      user = user[4:]
    elif user.find('@') == -1:
      user = '%s@%s' % (user, domain)
    sys.stderr.write('updating user %s...\n' % user)
    if do_update_user:
      callGAPIBatch(service=directoryObj.users(), function='patch', callback=process_update_users, userKey=user, body=body, fields='primaryEmail')
    if do_admin_user:
      callGAPIBatch(service=directoryObj.users(), function='makeAdmin', callback=process_update_users, userKey=user, body={'status': is_admin})

def memberAddCallback(request_id, response, exception):
  if exception is not None:
    print exception
  else:
    print '%s %s added as a %s' % (response['type'], response['email'], response['role'])

def memberUpdateCallback(request_id, response, exception):
  if exception is not None:
    print exception
  else:
    print '%s %s updated to a %s' % (response['type'], response['email'], response['role'])

def memberRemoveCallback(request_id, response, exception):
  if exception is not None:
    print exception
  else:
    print 'Remove %s succeeded.' % request_id

def GroupUpdateCallback(request_id, response, exception):
  if exception is not None:
    print exception
  else:
    print response

def doUpdateGroup():
  group = argv[3]
  if argv[4].lower() in ['add', 'update', 'sync', 'remove']:
    directoryObj = buildGAPIObject('directory')
    if group[0:3].lower() == 'uid:':
      group = group[4:]
    elif group.find('@') == -1:
      group = '%s@%s' % (group, domain)
    if argv[4].lower() == 'add' or argv[4].lower() == 'update':
      role = argv[5].upper()
      i = 6
      if role != 'OWNER' and role != 'MANAGER' and role != 'MEMBER':
        role = 'MEMBER'
        i = 5
      if argv[i].lower() in ['user', 'group', 'ou', 'org', 'file', 'all']:
        users_email = getUsersToModify(entity_type=argv[i], entity=argv[i+1])
      else:
        users_email = [argv[i],]
      for user_email in users_email:
        if user_email != '*' and user_email.find('@') == -1:
          user_email = '%s@%s' % (user_email, domain)
        sys.stderr.write(' %sing %s %s...\n' % (argv[4].lower(), role.lower(), user_email))
        if argv[4].lower() == 'add':
          body = {'role': role}
          body['email'] = user_email 
          callGAPIBatch(service=directoryObj.members(), function='insert', callback=memberAddCallback, groupKey=group, body=body)
        elif argv[4].lower() == 'update':
          callGAPIBatch(service=directoryObj.members(), function='update', callback=memberUpdateCallback, groupKey=group, memberKey=user_email, body={'email': user_email, 'role': role})
      return
    elif argv[4].lower() == 'sync':
      role = argv[5].upper()
      i = 6
      if role != 'OWNER' and role != 'MANAGER' and role != 'MEMBER':
        role = 'MEMBER'
        i = 5
      users_email = getUsersToModify(entity_type=argv[i], entity=argv[i+1])
      users_email = [x.lower() for x in users_email]
      current_emails = getUsersToModify(entity_type='group', entity=group)
      current_emails = [x.lower() for x in current_emails]
      to_add = list(set(users_email) - set(current_emails))
      to_remove = list(set(current_emails) - set(users_email))
      for user_email in to_add:
        sys.stderr.write(' adding %s %s\n' % (role, user_email))
        callGAPIBatch(service=directoryObj.members(), function='insert', callback=memberAddCallback, groupKey=group, body={'email': user_email, 'role': role})
      for user_email in to_remove:
        sys.stderr.write(' removing %s\n' % user_email)
        callGAPIBatch(service=directoryObj.members(), function='delete', callback=memberRemoveCallback, groupKey=group, memberKey=user_email)
    elif argv[4].lower() == 'remove':
      i = 5
      if argv[i].lower() in ['member', 'manager', 'owner']:
        i += 1
      if argv[i].lower() in ['user', 'group', 'ou', 'org', 'file', 'all']:
        user_emails = getUsersToModify(entity_type=argv[i], entity=argv[i+1])
      else:
        user_emails = [argv[i],]
      for user_email in user_emails:
        if user_email != '*' and user_email.find('@') == -1:
          user_email = '%s@%s' % (user_email, domain)
        sys.stderr.write(' removing %s\n' % user_email)
        callGAPIBatch(service=directoryObj.members(), function='delete', callback=memberRemoveCallback, groupKey=group, memberKey=user_email)
  else:
    i = 4
    use_cd_api = False
    use_gs_api = False
    gs_body = dict()
    cd_body = dict()
    allow_external_members = allow_google_communication = allow_web_posting = archive_only = custom_reply_to = default_message_deny_notification_text = description = is_archived = max_message_bytes = members_can_post_as_the_group = message_display_font = message_moderation_level = name = primary_language = reply_to = send_message_deny_notification = show_in_group_directory = who_can_invite =  who_can_join = who_can_post_message = who_can_view_group = who_can_view_membership = include_in_global_address_list = spam_moderation_level = None
    true_false = ['true', 'false']
    while i < len(argv):
      if argv[i].lower() == 'email':
        use_cd_api = True
        cd_body['email'] = argv[i+1]
        i += 2
      elif argv[i].lower() == 'admincreated':
        use_cd_api = True
        cd_body['adminCreated'] = argv[i+1].lower()
        if cd_body['adminCreated'] not in true_false:
          print 'Error: Value for admincreated must be true or false. Got %s' % admin_created
          return 9
        i += 2
      elif argv[i].lower() in ['allow_external_members', 'allowexternalmembers']:
        use_gs_api = True
        gs_body['allowExternalMembers'] = argv[i+1].lower()
        if gs_body['allowExternalMembers'] not in true_false:
          print 'Error: Value for allow_external_members must be true or false. Got %s' % gs_body['allowExternalMembers']
          return 9
        i += 2
      elif argv[i].lower() in ['include_in_global_address_list', 'includeinglobaladdresslist']:
        use_gs_api = True
        gs_body['includeInGlobalAddressList'] = argv[i+1].lower()
        if gs_body['includeInGlobalAddressList'] not in true_false:
          print 'Error: Value for include_in_global_address_list must be true or false. Got %s' % gs_body['includeInGlobalAddressList']
          return 9
        i += 2
      elif argv[i].lower() in ['spam_moderation_level', 'spammoderationlevel']:
        use_gs_api = True
        gs_body['spamModerationLevel'] = argv[i+1].upper()
        if gs_body['spamModerationLevel'] not in ['ALLOW', 'MODERATE', 'SILENTLY_MODERATE', 'REJECT']:
          print 'Error: Value for spam_moderation_level must be allow, moderate, silently_moderate or reject. Got %s' % gs_body['spamModerationLevel']
          return 9
        i += 2
      elif argv[i].lower() in ['message_moderation_level', 'messagemoderationlevel']:
        use_gs_api = True
        gs_body['messageModerationLevel'] = argv[i+1].upper()
        if gs_body['messageModerationLevel'] not in ['MODERATE_ALL_MESSAGES', 'MODERATE_NEW_MEMBERS', 'MODERATE_NONE', 'MODERATE_NON_MEMBERS']:
          print 'Error: Value for message_moderation_level must be moderate_all_messages, moderate_new_members, moderate_none or moderate_non_members. Got %s' % gs_body['messageModerationLevel']
          return 9
        i += 2
      elif argv[i].lower() == 'name':
        use_cd_api = True
        cd_body['name'] = argv[i+1]
        i += 2
      elif argv[i].lower() in ['primary_language', 'primarylanguage']:
        use_gs_api = True
        gs_body['primaryLanguage'] = argv[i+1]
        i += 2
      elif argv[i].lower() in ['reply_to', 'replyto']:
        use_gs_api = True
        gs_body['replyTo'] = argv[i+1].upper()
        if gs_body['replyTo'] not in ['REPLY_TO_CUSTOM', 'REPLY_TO_IGNORE', 'REPLY_TO_LIST', 'REPLY_TO_MANAGERS', 'REPLY_TO_OWNER', 'REPLY_TO_SENDER']:
          print 'Error: Value for reply_to must be reply_to_custom, reply_to_ignore, reply_to_list, reply_to_managers, reply_to_owner or reply_to_sender. Got %s' % gs_body['replyTo']
          return 9
        i += 2
      elif argv[i].lower() in ['send_message_deny_notification', 'sendmessagedenynotification']:
        use_gs_api = True
        gs_body['sendMessageDenyNotification'] = argv[i+1].lower()
        if gs_body['sendMessageDenyNotification'] not in true_false:
          print 'Error: Value for send_message_deny_notification must be true or false. Got %s' % gs_body['sendMessageDenyNotification']
          return 9
        i += 2
      elif argv[i].lower() in ['show_in_groups_directory', 'show_in_group_directory', 'showingroupdirectory']:
        use_gs_api = True
        gs_body['showInGroupDirectory'] = argv[i+1].lower()
        if gs_body['showInGroupDirectory'] not in true_false:
          print 'Error: Value for show_in_group_directory must be true or false. Got %s' % gs_body['showInGroupDirectory']
          return 9
        i += 2
      elif argv[i].lower() in ['who_can_invite', 'whocaninvite']:
        use_gs_api = True
        gs_body['whoCanInvite'] = argv[i+1].upper()
        if gs_body['whoCanInvite'] not in ['ALL_MANAGERS_CAN_INVITE', 'ALL_MEMBERS_CAN_INVITE']:
          print 'Error: Value for who_can_invite must be all_managers_can_invite or all_members_can_invite. Got %s' % gs_body['whoCanInvite']
          return 9
        i += 2
      elif argv[i].lower() in ['who_can_join', 'whocanjoin']:
        use_gs_api = True
        gs_body['whoCanJoin'] = argv[i+1].upper()
        if gs_body['whoCanJoin'] not in ['ALL_IN_DOMAIN_CAN_JOIN', 'ANYONE_CAN_JOIN', 'CAN_REQUEST_TO_JOIN', 'INVITED_CAN_JOIN']:
          print 'Error: Value for who_can_join must be all_in_domain_can_join, anyone_can_join, can_request_to_join or invited_can_join. Got %s' % gs_body['whoCanJoin']
          return 9
        i += 2
      elif argv[i].lower() in ['who_can_post_message', 'whocanpostmessage']:
        use_gs_api = True
        gs_body['whoCanPostMessage'] = argv[i+1].upper()
        if gs_body['whoCanPostMessage'] not in ['ALL_IN_DOMAIN_CAN_POST', 'ALL_MANAGERS_CAN_POST', 'ALL_MEMBERS_CAN_POST', 'ANYONE_CAN_POST', 'NONE_CAN_POST']:
          print 'Error: Value for who_can_post_message must be all_in_domain_can_post, all_managers_can_post, all_members_can_post, anyone_can_post or none_can_post. Got %s' % gs_body['whoCanPostMessage']
          return 9
        i += 2
      elif argv[i].lower() in ['who_can_view_group', 'whocanviewgroup']:
        use_gs_api = True
        gs_body['whoCanViewGroup'] = argv[i+1].upper()
        if gs_body['whoCanViewGroup'] not in ['ALL_IN_DOMAIN_CAN_VIEW', 'ALL_MANAGERS_CAN_VIEW', 'ALL_MEMBERS_CAN_VIEW', 'ANYONE_CAN_VIEW']:
          print 'Error: Value for who_can_view_group must be all_in_domain_can_view, all_managers_can_view, all_members_can_view or anyone_can_view. Got %s' % gs_body['whoCanViewGroup']
          return 9
        i += 2
      elif argv[i].lower() in ['who_can_view_membership', 'whocanviewmembership']:
        use_gs_api = True
        gs_body['whoCanViewMembership'] = argv[i+1].upper()
        if gs_body['whoCanViewMembership'] not in ['ALL_IN_DOMAIN_CAN_VIEW', 'ALL_MANAGERS_CAN_VIEW', 'ALL_MEMBERS_CAN_VIEW']:
          print 'Error: Value for who_can_view_membership must be all_in_domain_can_view, all_managers_can_view or all_members_can_view. Got %s' % gs_body['whoCanViewMembership']
          return 9
        i += 2
      elif argv[i].lower() in ['allow_google_communication', 'allowgooglecommunication']:
        use_gs_api = True
        gs_body['allowGoogleCommunication'] = argv[i+1].lower()
        if gs_body['allowGoogleCommunication'] not in true_false:
          print 'Error: Value for allow_google_communication must be true or false. Got %s' % gs_body['allowGoogleCommunication']
          return 9
        i += 2
      elif argv[i].lower() in ['allow_web_posting', 'allowwebposting']:
        use_gs_api = True
        gs_body['allowWebPosting'] = argv[i+1].lower()
        if gs_body['allowWebPosting'] not in true_false:
          print 'Error: Value for allow_web_posting must be true or false. Got %s' % gs_body['allowWebPosting']
          return 9
        i += 2
      elif argv[i].lower() in ['archive_only', 'archiveonly']:
        use_gs_api = True
        gs_body['archiveOnly'] = argv[i+1].lower()
        if gs_body['archiveOnly'] not in true_false:
          print 'Error: Value for archive_only must be true or false. Got %s' % gs_body['archiveOnly']
          return 9
        i += 2
      elif argv[i].lower() in ['custom_reply_to', 'customreplyto']:
        use_gs_api = True
        gs_body['customReplyTo'] = argv[i+1]
        i += 2
      elif argv[i].lower() in ['default_message_deny_notification_text', 'defaultmessagedenynotificationtext']:
        use_gs_api = True
        gs_body['defaultMessageDenyNotificationText'] = argv[i+1]
        i += 2
      elif argv[i].lower() == 'description':
        use_cd_api = True
        cd_body['description'] = argv[i+1]
        i += 2
      elif argv[i].lower() in ['is_archived', 'isarchived']:
        use_gs_api = True
        gs_body['isArchived'] = argv[i+1].lower()
        if gs_body['isArchived'] not in true_false:
          print 'Error: Value for is_archived must be true or false. Got %s' % gs_body['isArchived']
          return 9
        i += 2
      elif argv[i].lower() in ['max_message_bytes', 'maxmessagebytes']:
        use_gs_api = True
        gs_body['maxMessageBytes'] = argv[i+1]
        try:
          if gs_body['maxMessageBytes'][-1:].upper() == 'M':
            gs_body['maxMessageBytes'] = str(int(gs_body['maxMessageBytes'][:-1]) * 1024 * 1024)
          elif gs_body['maxMessageBytes'][-1:].upper() == 'K':
            gs_body['maxMessageBytes'] = str(int(gs_body['maxMessageBytes'][:-1]) * 1024)
          elif gs_body['maxMessageBytes'][-1].upper() == 'B':
            gs_body['maxMessageBytes'] = str(int(gs_body['maxMessageBytes'][:-1]))
          else:
            gs_body['maxMessageBytes'] = str(int(gs_body['maxMessageBytes']))
        except ValueError:
          print 'Error: max_message_bytes must be a number ending with M (megabytes), K (kilobytes) or nothing (bytes). Got %s' % gs_body['maxMessageBytes']
          return 9
        i += 2
      elif argv[i].lower() in ['members_can_post_as_the_group', 'memberscanpostasthegroup']:
        use_gs_api = True
        gs_body['membersCanPostAsTheGroup'] = argv[i+1].lower()
        if gs_body['membersCanPostAsTheGroup'] not in true_false:
          print 'Error: Value for members_can_post_as_the_group must be true or false. Got %s' % gs_body['membersCanPostAsTheGroup']
          return 9
        i += 2
      elif argv[i].lower() in ['message_display_font', 'messagedisplayfont']:
        use_gs_api = True
        gs_body['messageDisplayFont'] = argv[i+1].upper()
        if gs_body['messageDisplayFont'] not in ['DEFAULT_FONT', 'FIXED_WIDTH_FONT']:
          print 'Error: Value for message_display_font must be default_font or fixed_width_font. Got %s' % gs_body['messageDisplayFont']
          return 9
        i += 2
      elif argv[i].lower() == 'settings':
        i += 1
      else:
        print 'Error: %s is not a valid setting for groups' % argv[i]
        return 10
    if group[:4].lower() == 'uid:': # group settings API won't take uid so we make sure cd API is used so that we can grab real email.
      use_cd_api = True
      group = group[4:]
    elif group.find('@') == -1:
      directoryObj = buildGAPIObject('directory')
      group = '%s@%s' % (group, domain)
    if use_cd_api:
      directoryObj = buildGAPIObject('directory')
      try:
        if cd_body['email'].find('@') == -1:
          cd_body['email'] = '%s@%s' % (cd_body['email'], domain)
      except KeyError:
        pass
      callGAPIBatch(service=directoryObj.groups(), function='patch', callback=GroupUpdateCallback, groupKey=group, body=cd_body)
    if use_gs_api:
      groupssettingsObj = buildGAPIObject('groupssettings')
      if use_cd_api:
        group = cd_result['email']
      callGAPIBatch(service=groupssettingsObj.groups(), function='patch', callback=GroupUpdateCallback, groupUniqueId=group, body=gs_body)

def doUpdateResourceCalendar():
  id = argv[3]
  common_name = None
  description = None
  type = None
  i = 4
  while i < len(argv):
    if argv[i].lower() == 'name':
      common_name = argv[i+1]
      i += 2
    elif argv[i].lower() == 'description':
      description = argv[i+1]
      i += 2
    elif argv[i].lower() == 'type':
      type = argv[i+1]
      i += 2
  rescal = getResCalObject()
  callGData(service=rescal, function='UpdateResourceCalendar', id=id, common_name=common_name, description=description, type=type)

def doUpdateCros():
  deviceId = argv[3]
  directoryObj = buildGAPIObject('directory')
  if deviceId[:6].lower() == 'query:':
    query = deviceId[6:]
    devices_result = callGAPIpages(service=directoryObj.chromeosdevices(), function='list', items='chromeosdevices', query=query, customerId=customerId, fields='chromeosdevices/deviceId,nextPageToken')
    devices = list()
    for a_device in devices_result:
      devices.append(a_device['deviceId'])
  else:
    devices = [deviceId,]
  i = 4
  body = dict()
  while i < len(argv):
    if argv[i].lower() == 'user':
      body['annotatedUser'] = argv[i + 1]
      i += 2
    elif argv[i].lower() == 'location':
      body['annotatedLocation'] = argv[i + 1]
      i += 2
    elif argv[i].lower() == 'notes':
      body['notes'] = argv[i + 1]
      i += 2
    elif argv[i].lower() in ['ou', 'org']:
      body['orgUnitPath'] = argv[i+1]
      if body['orgUnitPath'][0] != '/':
        body['orgUnitPath'] = '/%s' % body['orgUnitPath']
      i += 2
    else:
      print 'Error: %s is not a valid argument for gam update cros' % argv[i]
      return 5
  device_count = len(devices)
  i = 1
  for this_device in devices:
    print ' updating %s (%s of %s)' % (this_device, i, device_count)
    callGAPIBatch(service=directoryObj.chromeosdevices(), function='patch', callback=generic_callback, deviceId=this_device, body=body, customerId=customerId)
    i += 1

def doUpdateMobile():
  resourceId = argv[3]
  directoryObj = buildGAPIObject('directory')
  i = 4
  action_body = patch_body = dict()
  doPatch = doAction = False
  while i < len(argv):
    if argv[i].lower() == 'action':
      action_body['action'] = argv[i+1].lower()
      if action_body['action'] == 'wipe':
        action_body['action'] = 'admin_remote_wipe'
      if action_body['action'] not in ['admin_remote_wipe', 'approve', 'block', 'cancel_remote_wipe_then_activate', 'cancel_remote_wipe_then_block']:
        print 'Error: action must be wipe, approve, block, cancel_remote_wipe_then_activate or cancel_remote_wipe_then_block. Got %s' % action_body['action']
        return 5
      doAction = True
      i += 2
    elif argv[i].lower() == 'model':
      patch_body['model'] = argv[i+1]
      i += 2
      doPatch = True
    elif argv[i].lower() == 'os':
      patch_body['os'] = argv[i+1]
      i += 2
      doPatch = True
    elif argv[i].lower() == 'useragent':
      patch_body['userAgent'] = argv[i+1]
      i += 2
      doPatch = True
    else:
      print 'Error: %s is not a valid argument for gam update cros' % argv[i]
      return 5
  if doPatch:
    callGAPI(service=directoryObj.mobiledevices(), function='patch', resourceId=resourceId, body=patch_body, customerId=customerId)
  if doAction:
    callGAPI(service=directoryObj.mobiledevices(), function='action', resourceId=resourceId, body=action_body, customerId=customerId)

def doDeleteMobile():
  directoryObj = buildGAPIObject('directory')
  resourceId = argv[3]
  callGAPI(service=directoryObj.mobiledevices(), function='delete', resourceId=resourceId, customerId=customerId)

def doUpdateOrg():
  orgUnitPath = argv[3]
  if orgUnitPath[0] != '/':
    orgUnitPath = '/'+orgUnitPath
  directoryObj = buildGAPIObject('directory')
  if argv[4].lower() in ['move', 'add']:
    if argv[5].lower() in ['user', 'users', 'cros', 'group', 'ou', 'org', 'file', 'all']:
      users = getUsersToModify(entity_type=argv[5], entity=argv[6])
    else:
      users = [argv[5],]
    if argv[5].lower() == 'cros':
      cros_count = len(users)
      current_cros = 1
      for cros in users:
        sys.stderr.write(' moving %s to %s (%s/%s)\n' % (cros, orgUnitPath, current_cros, cros_count))
        callGAPI(service=directoryObj.chromeosdevices(), function='patch', customerId=customerId, deviceId=cros, body={'orgUnitPath': orgUnitPath})
        current_cros += 1
    else:
      user_count = len(users)
      current_user = 1
      for user in users:
        if user[:4].lower() == 'uid:':
          user = user[4:]
        elif user.find('@') == -1:
          user = '%s@%s' % (user, domain)
        sys.stderr.write(' moving %s to %s (%s/%s)\n' % (user, orgUnitPath, current_user, user_count))
        try:
          callGAPI(service=directoryObj.users(), function='patch', throw_reasons=['conditionNotMet'], userKey=user, body={'orgUnitPath': orgUnitPath})
        except apiclient.errors.HttpError:
          pass
        current_user += 1
  else:
    body = dict()
    i = 4
    while i < len(argv):
      if argv[i].lower() == 'name':
        body['name'] = argv[i+1]
        i += 2
      elif argv[i].lower() == 'description':
        body['description'] = argv[i+1]
        i += 2
      elif argv[i].lower() == 'parent':
        body['parentOrgUnitPath'] = argv[i+1]
        if body['parentOrgUnitPath'][0] != '/':
          body['parentOrgUnitPath'] = '/'+body['parentOrgUnitPath']
        i += 2
      elif argv[i].lower() == 'noinherit':
        body['blockInheritance'] = True
        i += 1
      elif argv[i].lower() == 'inherit':
        body['blockInheritance'] = False
        i += 1
    callGAPI(service=directoryObj.orgunits(), function='patch', customerId=customerId, orgUnitPath=orgUnitPath, body=body)

def doWhatIs():
  email = argv[2]
  directoryObj = buildGAPIObject('directory')
  if email.find('@') == -1:
    email = '%s@%s' % (email, domain)
  try:
    user_or_alias = callGAPI(service=directoryObj.users(), function='get', throw_reasons=['badRequest', 'invalid'], userKey=email, fields='primaryEmail')
    if user_or_alias['primaryEmail'].lower() == email.lower():
          sys.stderr.write('%s is a user\n\n' % email)
          doGetUserInfo(user_email=email)
          return
    else:
      sys.stderr.write('%s is a user alias\n\n' % email)
      doGetAliasInfo(alias_email=email)
      return
  except apiclient.errors.HttpError:
    sys.stderr.write('%s is not a user...\n' % email)
    sys.stderr.write('%s is not a user alias...\n' % email)
  try:
    group = callGAPI(service=directoryObj.groups(), function='get', throw_reasons='badRequest', groupKey=email, fields='email')
  except apiclient.errors.HttpError:
    sys.stderr.write('%s is not a group either!\n\nDoesn\'t seem to exist!' % email)
    return 0
  if group['email'].lower() == email.lower():
    sys.stderr.write('%s is a group\n\n' % email)
    doGetGroupInfo(group_name=email)
  else:
    sys.stderr.write('%s is a group alias\n\n' % email)
    doGetAliasInfo(alias_email=email)

def doGetUserInfo(user_email=None):
  directoryObj = buildGAPIObject('directory')
  if user_email == None:
    try:
      user_email = argv[3]
    except IndexError:
      oauth2file = getGamPath()+'oauth2.txt'
      try:
        oauth2file = getGamPath()+os.environ['OAUTHFILE']
      except KeyError:
        pass
      storage = oauth2client.file.Storage(oauth2file)
      credentials = storage.get()
      if credentials is None or credentials.invalid:
        doRequestOAuth()
      credentials = storage.get()
      user_email = credentials.id_token['email']
  if user_email[:4].lower() == 'uid:':
    user_email = user_email[4:]
  elif user_email.find('@') == -1:
    user_email = '%s@%s' % (user_email, domain)
  getAliases = getGroups = True
  i = 4
  while i < len(argv):
    if argv[i].lower() == 'noaliases':
      getAliases = False
      i += 1
    elif argv[i].lower() == 'nogroups':
      getGroups = False
      i += 1
    else:
      print '%s is not a valid argument for gam info user' % argv[i]
      return 3
  user = callGAPI(service=directoryObj.users(), function='get', userKey=user_email)
  if type(user) is int:
    return
  print 'User: %s' % user['primaryEmail']
  try:
    print 'First Name: %s' % user['name']['givenName']
  except KeyError:
    print 'First Name: <blank>'
  try:
    print 'Last Name: %s' % user['name']['familyName']
  except KeyError:
    print 'Last Name: <blank>'
  print 'Is a Super Admin: %s' % user['isAdmin']
  print 'Is Delegated Admin: %s' % user['isDelegatedAdmin']
  print 'Has Agreed to Terms: %s' % user['agreedToTerms']
  print 'IP Whitelisted: %s' % user['ipWhitelisted']
  print 'Account Suspended: %s' % user['suspended']
  try:
    print 'Suspension Reason: %s' % user['suspensionReason']
  except KeyError:
    pass
  print 'Must Change Password: %s' % user['changePasswordAtNextLogin']
  print 'Google Unique ID: %s' % user['id']
  print 'Customer ID: %s' % user['customerId']
  print 'Mailbox is setup: %s' % user['isMailboxSetup']
  print 'Included in GAL: %s' % user['includeInGlobalAddressList']
  print 'Creation Time: %s' % user['creationTime']
  if user['lastLoginTime'] == u'1970-01-01T00:00:00.000Z':
    print 'Last login time: Never'
  else:
    print 'Last login time: %s' % user['lastLoginTime']
  try:
    print 'Google Org Unit Path: %s\n' % user['orgUnitPath']
  except KeyError:
    print 'Google Org Unit Path: Unknown\n'
  try:
    print 'Photo URL: https://plus.google.com%s\n' % user['thumbnailPhotoUrl']
  except KeyError:
    pass
  print 'IMs:'
  try:
    for im in user['ims']:
      for key in im.keys():
        print ' %s: %s' % (key, im[key])
      print ''
  except KeyError:
    pass
  print 'Addresses:'
  try:
    for address in user['addresses']:
      for key in address.keys():
        print ' %s: %s' % (key, address[key])
      print ''
  except KeyError:
    pass
  print 'Organizations:'
  try:
    for org in user['organizations']:
      for key in org.keys():
        print ' %s: %s' % (key, org[key])
      print ''
  except KeyError:
    pass
  print 'Phones:'
  try:
    for phone in user['phones']:
      for key in phone.keys():
        print ' %s: %s' % (key, phone[key])
      print ''
  except KeyError:
    pass
  print 'Relations:'
  try:
    for relation in user['relations']:
      for key in relation.keys():
        if key == 'type' and relation[key] == 'custom':
          continue
        elif key == 'customType':
          print ' %s: %s' % ('type', relation[key])
        else:
          print ' %s: %s' % (key, relation[key])
      print ''
  except KeyError:
    pass
  print 'External IDs:'
  try:
    for id in user['externalIds']:
      for key in id.keys():
        if key == 'type' and id[key] == 'custom':
          continue
        elif key == 'customType':
          print ' %s: %s' % ('type', id[key])
        else:
          print ' %s: %s' % (key, id[key])
      print ''
  except KeyError:
    pass
  if getAliases:
    print 'Email Aliases:'
    try:
      for alias in user['aliases']:
        print '  ' + alias
    except KeyError:
      pass
    print 'Non-Editable Aliases:'
    try:
      for alias in user['nonEditableAliases']:
        print '  ' + alias
    except KeyError:
      pass
  if getGroups:
    groups = callGAPI(service=directoryObj.groups(), function='list', userKey=user_email)
    print 'Groups:'
    try:
      for group in groups['groups']:
        print '  ' + group['name'] + ' <' + group['email'] + '>'
    except KeyError:
      pass

def doGetGroupInfo(group_name=None):
  if group_name == None:
    group_name = argv[3]
  get_users = True
  try:
    if argv[4].lower() == 'nousers':
      get_users = False
  except IndexError:
    pass
  directoryObj = buildGAPIObject('directory')
  groupssettingsObj = buildGAPIObject('groupssettings')
  if group_name[:4].lower() == 'uid:':
    group_name = group_name[4:]
  elif group_name.find('@') == -1:
    group_name = group_name+'@'+domain
  basic_info = callGAPI(service=directoryObj.groups(), function='get', groupKey=group_name)
  try:
    settings = callGAPI(service=groupssettingsObj.groups(), function='get', groupUniqueId=basic_info['email'], throw_reasons='authError') # Use email address retrieved from cd since GS API doesn't support uid
  except apiclient.errors.HttpError:
    pass
  print ''
  print 'Group Settings:'
  for key, value in basic_info.items():
    if key == 'kind':
      continue
    elif type(value) == type(list()):
      print ' %s:' % key
      for val in value:
        print '  %s' % val
    else:
      print ' %s: %s' % (key, value)
  try:
    for key, value in settings.items():
      if key in ['kind', 'description', 'email', 'name']:
        continue
      elif key == 'maxMessageBytes':
        if value > 1024*1024:
          value = '%sM' % (value / 1024 / 1024)
        elif value > 1024:
          value = '%sK' % (value / 1024)
      print ' %s: %s' % (key, value)
  except UnboundLocalError:
    pass
  if get_users:
    members = callGAPIpages(service=directoryObj.members(), function='list', items='members', groupKey=group_name)
    print 'Members:'
    for member in members:
      try:
        print ' %s: %s (%s)' % (member['role'].lower(), member['email'], member['type'].lower())
      except KeyError:
        try:
          print ' member: %s (%s)' % (member['email'], member['type'].lower())
        except KeyError:
          print ' member: %s (%s)' % (member['id'], member['type'].lower())
    print 'Total %s users in group' % len(members)

def handleGAPIException(exception):
  print 'Exception: %s' % exception

def printAliasInfo(request_id, response, exception):
  if exception is not None:
    handleGAPIException(exception)
  else:
    print response
    print ' Alias Email: %s' % alias_email
    try:
      if result['primaryEmail'].lower() == alias_email.lower():
        print 'Error: %s is a primary user email address, not an alias.' % alias_email
        return 3
      print ' User Email: %s' % result['primaryEmail']
      print 'User Unique ID: %s' % result['id']
    except KeyError:
      print ' Group Email: %s' % result['email']
      print 'Group Unique ID: %s' % result['id']

def doGetAliasInfo(alias_email=None):
  directoryObj = buildGAPIObject('directory')
  if alias_email == None:
    alias_email = argv[3]
  if alias_email.find('@') == -1:
    alias_email = '%s@%s' % (alias_email, domain)
  cd_batch.add(directoryObj.users().aliases().list(userKey=alias_email), callback=printAliasInfo)

def doGetResourceCalendarInfo():
  id = argv[3]
  rescal = getResCalObject()
  result = callGData(service=rescal, function='RetrieveResourceCalendar', id=id)
  print ' Resource ID: '+result['resourceId']
  print ' Common Name: '+result['resourceCommonName']
  print ' Email: '+result['resourceEmail']
  try:
    print ' Type: '+result['resourceType']
  except KeyError:
    print ' Type: '
  try:
    print ' Description: '+result['resourceDescription']
  except KeyError:
    print ' Description: '

def doGetCrosInfo():
  deviceId = argv[3]
  directoryObj = buildGAPIObject('directory')
  info = callGAPI(service=directoryObj.chromeosdevices(), function='get', customerId=customerId, deviceId=deviceId)
  for key, value in info.items():
    if key == 'kind':
      continue
    print ' %s: %s' % (key, value)

def doGetMobileInfo():
  deviceId = argv[3]
  directoryObj = buildGAPIObject('directory')
  info = callGAPI(service=directoryObj.mobiledevices(), function='get', customerId=customerId, resourceId=deviceId)
  for key, value in info.items():
    if key == 'kind':
      continue
    if key == 'name' or key == 'email':
      value = value[0]
    print ' %s: %s' % (key, value)

def doGetOrgInfo():
  name = argv[3]
  get_users = True
  try:
    if argv[4].lower() == 'nousers':
      get_users = False
  except IndexError:
    pass
  if len(name) > 1 and name[0] == '/':
    name = name[1:]
  directoryObj = buildGAPIObject('directory')
  result = callGAPI(service=directoryObj.orgunits(), function='get', customerId=customerId, orgUnitPath=name)
  print 'Organization Unit: %s' % result['name']
  try:
    print 'Description: %s' % result['description']
  except KeyError:
    print 'Description: '
  print 'Parent Org: %s' % result['parentOrgUnitPath']
  print 'Full Org Path: %s' % result['orgUnitPath']
  try:
    print 'Block Inheritance: %s' % result['blockInheritance']
  except KeyError:
    print 'Block Inheritance: False'
  if get_users:
    print 'Users: '
    users = getUsersToModify(entity_type='ou', entity=name, silent=True)
    for user in users:
      print ' %s' % user

def doUpdateDomain():
  adminObj = getAdminSettingsObject()
  command = argv[3].lower()
  if command == 'language':
    language = argv[4]
    callGData(service=adminObj, function='UpdateDefaultLanguage', defaultLanguage=language)
  elif command == 'name':
    name = argv[4]
    callGData(service=adminObj, function='UpdateOrganizationName', organizationName=name)
  elif command == 'admin_secondary_email':
    admin_secondary_email = argv[4]
    callGData(service=adminObj, function='UpdateAdminSecondaryEmail', adminSecondaryEmail=admin_secondary_email)
  elif command == 'logo':
    logo_file = argv[4]
    try:
      fp = open(logo_file, 'rb')
      logo_image = fp.read()
      fp.close()
    except IOError:
      print 'Error: can\'t open file %s' % logo_file
      return 11
    callGData(service=adminObj, function='UpdateDomainLogo', logoImage=logo_image)
  elif command == 'mx_verify':
    result = callGData(service=adminObj, function='UpdateMXVerificationStatus')
    print 'Verification Method: %s' % result['verificationMethod']
    print 'Verified: %s' % result['verified']
  elif command == 'sso_settings':
    enableSSO = samlSignonUri = samlLogoutUri = changePasswordUri = ssoWhitelist = useDomainSpecificIssuer = None
    i = 4
    while i < len(argv):
      if argv[i].lower() == 'enabled':
        if argv[i+1].lower() == 'true':
          enableSSO = True
        elif argv[i+1].lower() == 'false':
          enableSSO = False
        else:
          print 'Error: value for enabled must be true or false, got %s' % argv[i+1]
          exit(9)
        i += 2
      elif argv[i].lower() == 'sign_on_uri':
        samlSignonUri = argv[i+1]
        i += 2
      elif argv[i].lower() == 'sign_out_uri':
        samlLogoutUri = argv[i+1]
        i += 2
      elif argv[i].lower() == 'password_uri':
        changePasswordUri = argv[i+1]
        i += 2
      elif argv[i].lower() == 'whitelist':
        ssoWhitelist = argv[i+1]
        i += 2
      elif argv[i].lower() == 'use_domain_specific_issuer':
        if argv[i+1].lower() == 'true':
          useDomainSpecificIssuer = True
        elif argv[i+1].lower() == 'false':
          useDomainSpecificIssuer = False
        else:
          print 'Error: value for use_domain_specific_issuer must be true or false, got %s' % argv[i+1]
          return 9
        i += 2 
      else:
        print 'Error: unknown option for "gam update domain sso_settings...": %s' % argv[i]
        return 9
    callGData(service=adminObj, function='UpdateSSOSettings', enableSSO=enableSSO, samlSignonUri=samlSignonUri, samlLogoutUri=samlLogoutUri, changePasswordUri=changePasswordUri, ssoWhitelist=ssoWhitelist, useDomainSpecificIssuer=useDomainSpecificIssuer)
  elif command == 'sso_key':
    key_file = argv[4]
    try:
      fp = open(key_file, 'rb')
      key_data = fp.read()
      fp.close()
    except IOError:
      print 'Error: can\'t open file %s' % logo_file
      return 11
    callGData(service=adminObj, function='UpdateSSOKey', signingKey=key_data)
  elif command == 'user_migrations':
    value = argv[4].lower()
    if value != 'true' and value != 'false':
      print 'Error: value for user_migrations must be true or false, got %s' % argv[4]
      return 9
    result = callGData(service=adminObj, function='UpdateUserMigrationStatus', enableUserMigration=value)
  elif command == 'outbound_gateway':
    gateway = argv[4]
    mode = argv[6].upper()
    try:
      result = callGData(service=adminObj, function='UpdateOutboundGatewaySettings', smartHost=gateway, smtpMode=mode)
    except TypeError:
      pass
  elif command == 'email_route':
    i = 4
    while i < len(argv):
      if argv[i].lower() == 'destination':
        destination = argv[i+1]
        i += 2
      elif argv[i].lower() == 'rewrite_to':
        rewrite_to = argv[i+1].lower()
        if rewrite_to == 'true':
          rewrite_to = True
        elif rewrite_to == 'false':
          rewrite_to = False
        else: 
          print 'Error: value for rewrite_to must be true or false, got %s' % argv[i+1]
          return 9
        i += 2
      elif argv[i].lower() == 'enabled':
        enabled = argv[i+1].lower()
        if enabled == 'true':
          enabled = True
        elif enabled == 'false':
          enabled = False
        else:
          print 'Error: value for enabled must be true or false, got %s' % argv[i+1]
          return 9
        i += 2
      elif argv[i].lower() == 'bounce_notifications':
        bounce_notifications = argv[i+1].lower()
        if bounce_notifications == 'true':
          bounce_notifications = True
        elif bounce_notifications == 'false':
          bounce_notifications = False
        else:
          print 'Error: value for bounce_notifications must be true or false, got %s' % argv[i+1]
          return 9
        i += 2
      elif argv[i].lower() == 'account_handling':
        account_handling = argv[i+1].lower()
        if account_handling == 'all_accounts':
          account_handling = 'allAccounts'
        elif account_handling == 'provisioned_accounts':
          account_handling = 'provisionedAccounts'
        elif account_handling == 'unknown_accounts':
          account_handling = 'unknownAccounts'
        else:
          print 'Error: value for account_handling must be all_accounts, provisioned_account or unknown_accounts. Got %s' % argv[i+1]
          return 9
        i += 2
      else:
        print 'Error: invalid setting for "gam update domain email_route..."'
        return 10
    response = callGData(service=adminObj, function='AddEmailRoute', routeDestination=destination, routeRewriteTo=rewrite_to, routeEnabled=enabled, bounceNotifications=bounce_notifications, accountHandling=account_handling)
  else:
    print 'Error: that is not a valid "gam update domain" command'

def doGetDomainInfo():
  adminsettingsObj = buildGAPIObject('adminsettings')
  if len(argv) > 4 and argv[3].lower() == 'logo':
    target_file = argv[4]
    logo_image = adminObj.GetDomainLogo()
    try:
      fp = open(target_file, 'wb')
      fp.write(logo_image)
      fp.close()
    except IOError:
      print 'Error: can\'t open file %s for writing' % target_file
      return 11
    return 0
  print 'Google Apps Domain: %s' % domain
  directoryObj = buildGAPIObject('directory')
  customer_id = callGAPI(service=directoryObj.users(), function='list', fields='users(customerId)', domain=domain, maxResults=1)['users'][0]['customerId']
  print 'Customer ID: %s' % customer_id
  default_language = callGAPI(service=adminsettingsObj.defaultLanguage(), function='get', domainName=domain)
  print 'Default Language: %s' % default_language['entry']['apps$property'][0]['value']
  org_name = callGAPI(service=adminsettingsObj.organizationName(), function='get', domainName=domain)
  print 'Organization Name: %s' % org_name['entry']['apps$property'][0]['value']
  max_users = callGAPI(service=adminsettingsObj.maximumNumberOfUsers(), function='get', domainName=domain)
  print 'Maximum Users: %s' % max_users['entry']['apps$property'][0]['value']
  current_users = callGAPI(service=adminsettingsObj.currentNumberOfUsers(), function='get', domainName=domain)
  print 'Current Users: %s' % current_users['entry']['apps$property'][0]['value']
  is_dom_verified = callGAPI(service=adminsettingsObj.isVerified(), function='get', domainName=domain)
  print 'Domain is Verified: %s' % is_dom_verified['entry']['apps$property'][0]['value']
  domain_edition = callGAPI(service=adminsettingsObj.edition(), function='get', domainName=domain)
  print 'Domain Edition: %s' % domain_edition['entry']['apps$property'][0]['value']
  customer_pin = callGAPI(service=adminsettingsObj.customerPIN(), function='get', domainName=domain)
  print 'Customer PIN: %s' % customer_pin['entry']['apps$property'][0]['value']
  creation_time = callGAPI(service=adminsettingsObj.creationTime(), function='get', domainName=domain)
  print 'Domain Creation Time: %s' % creation_time['entry']['apps$property'][0]['value']
  country_code = callGAPI(service=adminsettingsObj.countryCode(), function='get', domainName=domain)
  print 'Domain Country Code: %s' % country_code['entry']['apps$property'][0]['value']
  mxverificationstatus = callGAPI(service=adminsettingsObj.mxVerification(), function='get', domainName=domain)
  for entry in mxverificationstatus['entry']['apps$property']:
    if entry['name'] == 'verified':
      print 'MX Verification Verified: %s' % entry['value']
    elif entry['name'] == 'verificationMethod':
      print 'MX Verification Method: %s' % entry['value']
  ssosettings = callGAPI(service=adminsettingsObj.ssoGeneral(), function='get', domainName=domain)
  for entry in ssosettings['entry']['apps$property']:
    if entry['name'] == 'enableSSO':
      print 'SSO Enabled: %s' % entry['value']
    elif entry['name'] == 'samlSignonUri':
      print 'SSO Signon Page: %s' % entry['value']
    elif entry['name'] == 'samlLogoutUri':
      print 'SSO Logout Page: %s' % entry['value']
    elif entry['name'] == 'changePasswordUri':
      print 'SSO Password Page: %s' % entry['value']
    elif entry['name'] == 'ssoWhitelist':
      print 'SSO Whitelist IPs: %s' % entry['value']
    elif entry['name'] == 'useDomainSpecificIssuer':
      print 'SSO Use Domain Specific Issuer: %s' % entry['value']
  ssokey = callGAPI(service=adminsettingsObj.ssoSigningKey(), function='get', silent_errors=True, domainName=domain)
  try:
    for entry in ssokey['entry']['apps$property']:
      if entry['name'] == 'algorithm':
        print 'SSO Key Algorithm: %s' % entry['value']
      elif entry['name'] == 'format':
        print 'SSO Key Format: %s' % entry['value']
      elif entry['name'] == 'modulus':
        print 'SSO Key Modulus: %s' % entry['value']
      elif entry['name'] == 'exponent':
        print 'SSO Key Exponent: %s' % entry['value']
      elif entry['name'] == 'yValue':
        print 'SSO Key yValue: %s' % entry['value']
      elif entry['name'] == 'signingKey':
        print 'Full SSO Key: %s' % entry['value']
  except TypeError:
    pass
  migration_status = callGAPI(service=adminsettingsObj.userEmailMigrationEnabled(), function='get', domainName=domain)
  print 'User Migration Enabled: %s' %  migration_status['entry']['apps$property'][0]['value']
  outbound_gateway_settings = {'smartHost': '', 'smtpMode': ''} # Initialize blank in case we get an 1801 Error
  outbound_gateway_settings = callGAPI(service=adminsettingsObj.outboundGateway(), function='get', domainName=domain)
  try:
    for entry in outbound_gateway_settings['entry']['apps$property']:
      if entry['name'] == 'smartHost':
        print 'Outbound Gateway Smart Host: %s' % entry['value']
      elif entry['name'] == 'smtpMode':
        print 'Outbound Gateway SMTP Mode: %s' % entry['value']
  except KeyError:
    print 'Outbound Gateway Smart Host: None'
    print 'Outbound Gateway SMTP Mode: None'

def delete_user_callback(request_id, response, exception):
  if exception is not None:
    print exception
  else:
    print response

def doDeleteUser():
  directoryObj = buildGAPIObject('directory')
  user_email = argv[3]
  if user_email[:4].lower() == 'uid:':
    user_email = user_email[4:]
  elif user_email.find('@') == -1:
    user_email = '%s@%s' % (user_email, domain)
  print "Deleting account for %s" % (user_email)
  callGAPIBatch(service=directoryObj.users(), function='delete', callback=delete_user_callback, userKey=user_email)

def doUndeleteUser():
  user = argv[3].lower()
  user_uid = False
  orgUnit = '/'
  try:
    if argv[3].lower() in ['ou', 'org']:
      orgUnit = argv[4]
  except IndexError:
    pass 
  directoryObj = buildGAPIObject('directory')
  if user[:4].lower() == 'uid:':
    user_uid = user[4:]
  elif user.find('@') == -1:
    user = '%s@%s' % (user, domain)
    user_domain = domain
  else:
    user_domain = user.split('@')[1]
  if not user_uid:
    print 'Looking up UID for %s...' % user
    deleted_users = callGAPIpages(service=directoryObj.users(), function='list', items='users', customer=customerId, showDeleted=True, maxResults=500)
    matching_users = list()
    for deleted_user in deleted_users:
      if str(deleted_user['primaryEmail']).lower() == user:
        matching_users.append(deleted_user)
    if len(matching_users) < 1:
      print 'ERROR: could not find deleted user with that address.'
      return 3
    elif len(matching_users) > 1:
      print 'ERROR: more than one matching deleted %s user. Please select the correct one to undelete and specify with "gam undelete user uid:<uid>"' % user
      print
      for matching_user in matching_users:
        print ' uid:%s ' % matching_user['id']
        for attr_name in ['creationTime', 'lastLoginTime', 'deletionTime']:
          try:
            if matching_user[attr_name] == '1970-01-01T00:00:00.000Z':
              matching_user[attr_name] = 'Never'
            print '   %s: %s ' % (attr_name, matching_user[attr_name])
          except KeyError:
            pass
        print
      return 3
    else:
      user_uid = matching_users[0]['id']
  print "Undeleting account for %s" % user
  callGAPI(service=directoryObj.users(), function='undelete', userKey=user_uid, body={'orgUnit': orgUnit})

def doDeleteGroup():
  group = argv[3]
  directoryObj = buildGAPIObject('directory')
  if group[:4].lower() == 'uid:':
    group = group[4:]
  elif group.find('@') == -1:
    group = '%s@%s' % (group, domain)
  print "Deleting group %s" % group
  callGAPI(service=directoryObj.groups(), function='delete', groupKey=group)

def doDeleteAlias(alias_email=None):
  is_user = is_group = False
  if alias_email == None:
    alias_email = argv[3]
  if alias_email.lower() == 'user':
    is_user = True
    alias_email = argv[4]
  elif alias_email.lower() == 'group':
    is_group = True
    alias_email = argv[4]
  directoryObj = buildGAPIObject('directory')
  if alias_email.find('@') == -1:
    alias_email = '%s@%s' % (alias_email, domain)
  print "Deleting alias %s" % alias_email
  if is_user or (not is_user and not is_group):
    try:
      callGAPI(service=directoryObj.users().aliases(), function='delete', throw_reasons=['invalid', 'badRequest', 'notFound'], userKey=alias_email, alias=alias_email)
      return
    except apiclient.errors.HttpError, e:
      error = json.loads(e.content)
      reason = error['error']['errors'][0]['reason']
      if reason == 'notFound':
        print 'Error: The alias %s does not exist' % alias_email
        return 4
  if not is_user or (not is_user and not is_group):
    callGAPI(service=directoryObj.groups().aliases(), function='delete', groupKey=alias_email, alias=alias_email)

def doDeleteResourceCalendar():
  res_id = argv[3]
  rescal = getResCalObject()
  print "Deleting resource calendar %s" % res_id
  callGData(service=rescal, function='DeleteResourceCalendar', id=res_id)

def doDeleteOrg():
  name = argv[3]
  directoryObj = buildGAPIObject('directory')
  if name[0] == '/':
    name = name[1:]
  print "Deleting organization %s" % name
  callGAPI(service=directoryObj.orgunits(), function='delete', customerId=customerId, orgUnitPath=name)

def output_csv(csv_list, titles, list_type, todrive):
  csv.register_dialect('nixstdout', lineterminator='\n')
  if todrive:
    import StringIO
    string_file = StringIO.StringIO()
    writer = csv.DictWriter(string_file, fieldnames=titles, dialect='nixstdout', quoting=csv.QUOTE_MINIMAL)
  else:
    writer = csv.DictWriter(sys.stdout, fieldnames=titles, dialect='nixstdout', quoting=csv.QUOTE_MINIMAL)
  csv_list = convertUTF8(csv_list)
  writer.writerows(csv_list)
  if todrive:
    columns = len(csv_list[0])
    rows = len(csv_list)
    cell_count = rows * columns
    convert = True
    if cell_count > 400000 or columns > 256:
      print 'Warning: results are to large for Google Spreadsheets. Uploading as a regular CSV file.'
      convert = False
    driveObj = buildGAPIObject('drive')
    string_data = string_file.getvalue()
    media = apiclient.http.MediaInMemoryUpload(string_data, mimetype='text/csv')
    result = callGAPI(service=driveObj.files(), function='insert', convert=convert, body={'description': ' '.join(argv), 'title': '%s - %s' % (domain, list_type), 'mimeType': 'text/csv'}, media_body=media)
    file_url = result['alternateLink']
    if os.path.isfile(getGamPath()+'nobrowser.txt'):
      print 'Drive file uploaded to:\n %s' % file_url
    else:
      import webbrowser
      webbrowser.open(file_url)

def doPrintUsers():
  directoryObj = buildGAPIObject('directory')
  fields = 'nextPageToken,users(primaryEmail'
  customer = customerId
  domain = None
  query = None
  getGroupFeed = False
  firstname = lastname = username = ou = suspended = changepassword = agreed2terms = admin = aliases = groups = id = creationtime = lastlogintime = fullname = gal = todrive = False
  deleted_only = orderBy = sortOrder = None
  user_attributes = []
  # the titles list ensures the CSV output has its parameters in the specified order. 
  # Python's dicts can be listed in any order, and the order often changes between the
  # header (user_attributes[0]) and the actual data rows.
  titles = ['Email']
  user_attributes.append({'Email': 'Email'})
  i = 3
  while i < len(argv):
    if argv[i].lower() == 'allfields':
      fields = '*'
      firstname = lastname = username = ou = suspended = changepassword = agreed2terms = admin = aliases = id = creationtime = lastlogintime = fullname = gal = True
      user_attributes[0].update(Firstname='Firstname', Lastname='Lastname', Fullname='Fullname', Username='Username', OU='OU', Suspended='Suspended', SuspensionReason='SuspensionReason', ChangePassword='ChangePassword', AgreedToTerms='AgreedToTerms', DelegatedAdmin='DelegatedAdmin', Admin='Admin', CreationTime='CreationTime', LastLoginTime='LastLoginTime', Aliases='Aliases', NonEditableAliases='NonEditableAliases', ID='ID', IncludeInGlobalAddressList='IncludeInGlobalAddressList')
      titles += ['Firstname', 'Lastname', 'Fullname', 'Username', 'OU', 'Suspended', 'SuspensionReason', 'ChangePassword', 'AgreedToTerms', 'DelegatedAdmin', 'Admin', 'CreationTime', 'LastLoginTime', 'Aliases', 'NonEditableAliases', 'ID', 'IncludeInGlobalAddressList']
      i += 1
    elif argv[i].lower() == 'todrive':
      todrive = True
      i += 1
    elif argv[i].lower() in ['deleted_only', 'only_deleted']:
      deleted_only = True
      i += 1
    elif argv[i].lower() == 'orderby':
      orderBy = argv[i+1]
      if orderBy.lower() not in ['email', 'familyname', 'givenname', 'firstname', 'lastname']:
        print 'Error: orderby should be email, familyName or givenName. Got %s' % orderBy
        return 3
      elif orderBy.lower() in ['familyname', 'lastname']:
        orderBy = 'familyName'
      elif orderBy.lower() in ['givenname', 'firstname']:
        orderBy= 'givenName'
      i += 2
    elif argv[i].lower() in ['ascending', 'descending']:
      sortOrder = argv[i].upper()
      i += 1
    elif argv[i].lower() == 'domain':
      domain = argv[i+1]
      customer = None
      i += 2
    elif argv[i].lower() == 'query':
      query = argv[i+1]
      i += 2
    elif argv[i].lower() in ['firstname', 'givenname']:
      fields += ',name'
      firstname = True
      user_attributes[0].update(Firstname='Firstname')
      titles.append('Firstname')
      i += 1
    elif argv[i].lower() in ['lastname', 'familyname']:
      if fields[-5:] != ',name':
        fields += ',name'
      lastname = True
      user_attributes[0].update(Lastname='Lastname')
      titles.append('Lastname')
      i += 1
    elif argv[i].lower() == 'fullname':
      if fields[-5:] != ',name':
        fields += ',name'
      fullname = True
      user_attributes[0].update(Fullname='Fullname')
      titles.append('Fullname')
      i += 1
    elif argv[i].lower() == 'username':
      username = True
      user_attributes[0].update(Username='Username')
      titles.append('Username')
      i += 1
    elif argv[i].lower() == 'ou':
      fields += ',orgUnitPath'
      ou = True
      user_attributes[0].update(OU='OU')
      titles.append('OU')
      i += 1
    elif argv[i].lower() == 'suspended':
      fields += ',suspended,suspensionReason'
      suspended = True
      user_attributes[0].update(Suspended='Suspended')
      titles.append('Suspended')
      user_attributes[0].update(SuspensionReason='SuspensionReason')
      titles.append('SuspensionReason')
      i += 1
    elif argv[i].lower() == 'changepassword':
      fields += ',changePasswordAtNextLogin'
      changepassword = True
      user_attributes[0].update(ChangePassword='ChangePassword')
      titles.append('ChangePassword')
      i += 1
    elif argv[i].lower() == 'agreed2terms':
      fields += ',agreedToTerms'
      agreed2terms = True
      user_attributes[0].update(AgreedToTerms='AgreedToTerms')
      titles.append('AgreedToTerms')
      i += 1
    elif argv[i].lower() == 'admin':
      fields += ',isAdmin,isDelegatedAdmin'
      admin = True
      user_attributes[0].update(Admin='Admin')
      titles.append('Admin')
      user_attributes[0].update(DelegatedAdmin='DelegatedAdmin')
      titles.append('DelegatedAdmin')
      i += 1
    elif argv[i].lower() == 'gal':
      fields += ',includeInGlobalAddressList'
      gal = True
      user_attributes[0].update(IncludeInGlobalAddressList='IncludeInGlobalAddressList')
      titles.append('IncludeInGlobalAddressList')
      i += 1
    elif argv[i].lower() == 'id':
      fields += ',id'
      id = True
      user_attributes[0].update(ID='ID')
      titles.append('ID')
      i += 1
    elif argv[i].lower() == 'creationtime':
      fields += ',creationTime'
      creationtime = True
      user_attributes[0].update(CreationTime='CreationTime')
      titles.append('CreationTime')
      i += 1
    elif argv[i].lower() == 'lastlogintime':
      fields += ',lastLoginTime'
      lastlogintime = True
      user_attributes[0].update(LastLoginTime='LastLoginTime')
      titles.append('LastLoginTime')
      i += 1
    elif argv[i].lower() == 'nicknames' or argv[i].lower() == 'aliases':
      fields += ',aliases,nonEditableAliases'
      aliases = True
      user_attributes[0].update(Aliases='Aliases')
      titles.append('Aliases')
      user_attributes[0].update(NonEditableAliases='NonEditableAliases')
      titles.append('NonEditableAliases')
      i += 1
    elif argv[i].lower() == 'groups':
      getGroupFeed = True
      groups = True
      user_attributes[0].update(Groups='Groups')
      titles.append('Groups')
      i += 1
    else:
      showUsage()
      exit(5)
  if fields != '*':
    fields += ')'
  sys.stderr.write("Getting all users in Google Apps account (may take some time on a large account)...\n")
  page_message = 'Got %%num_items%% users: %%first_item%% - %%last_item%%\n'
  all_users = callGAPIpages(service=directoryObj.users(), function='list', items='users', page_message=page_message, message_attribute='primaryEmail', customer=customer, domain=domain, fields=fields, showDeleted=deleted_only, maxResults=500, orderBy=orderBy, sortOrder=sortOrder, query=query)
  for user in all_users:
    email = user['primaryEmail'].lower()
    domain = email[email.find('@')+1:]
    if domain == 'gtempaccount.com':
      continue
    if email[:2] == '.@' or email[:11] == 'gcc_websvc@' or email[:27] == 'secure-data-connector-user@':  # not real users, skip em
      continue
    user_attributes.append({'Email': email})
    location = 0
    try:
      location = user_attributes.index({'Email': email})
      if username:
          user_attributes[location].update(Username=email[:email.find('@')])
      if ou:
          user_attributes[location].update(OU=user['orgUnitPath'])
      if firstname:
        try:
          user_attributes[location].update(Firstname=user['name']['givenName'])
        except KeyError:
          pass
      if lastname:
        try:
          user_attributes[location].update(Lastname=user['name']['familyName'])
        except KeyError:
          pass
      if fullname:
        try:
          user_attributes[location].update(Fullname=user['name']['fullName'])
        except KeyError:
          pass
      if suspended:
        try:
          user_attributes[location].update(Suspended=user['suspended'])
          user_attributes[location].update(SuspensionReason=user['suspensionReason'])
        except KeyError:
          pass
      if gal:
        try:
          user_attributes[location].update(IncludeInGlobalAddressList=user['includeInGlobalAddressList'])
        except KeyError:
          pass
      if agreed2terms:
        try:
          user_attributes[location].update(AgreedToTerms=user['agreedToTerms'])
        except KeyError:
          pass
      if changepassword:
        try:
          user_attributes[location].update(ChangePassword=user['changePasswordAtNextLogin'])
        except KeyError:
          pass
      if admin:
        try:
          user_attributes[location].update(Admin=user['isAdmin'])
          user_attributes[location].update(DelegatedAdmin=user['isDelegatedAdmin'])
        except KeyError:
          pass
      if id:
        try:
          user_attributes[location].update(ID=user['id'])
        except KeyError:
          pass
      if creationtime:
        try:
          user_attributes[location].update(CreationTime=user['creationTime'])
        except KeyError:
          pass
      if lastlogintime:
        try:
          if user['lastLoginTime'] == u'1970-01-01T00:00:00.000Z':
            user_attributes[location].update(LastLoginTime='Never')
          else:
            user_attributes[location].update(LastLoginTime=user['lastLoginTime'])
        except KeyError:
          pass
      if aliases:
        try:
          user_aliases = ''
          for alias in user['aliases']:
            user_aliases += ' %s' % alias
          if len(user_aliases) > 0:
            user_aliases = user_aliases[1:]
          user_attributes[location].update(Aliases=user_aliases)
        except KeyError:
          pass
        try:
          ne_aliases = ''
          for alias in user['nonEditableAliases']:
            ne_aliases += ' %s' % alias
          if len(ne_aliases) > 0:
            ne_aliases = ne_aliases[1:]
          user_attributes[location].update(NonEditableAliases=ne_aliases)
        except KeyError:
          pass
    except ValueError:
      raise
    except KeyError:
      pass
  if getGroupFeed:
    total_users = len(user_attributes) - 1
    user_count = 1
    for user in user_attributes[1:]:
      user_email = user['Email']
      sys.stderr.write("Getting Group Membership for %s (%s/%s)\r\n" % (user_email, user_count, total_users))
      groups = callGAPIpages(service=directoryObj.groups(), function='list', items='groups', userKey=user_email)
      grouplist = ''
      for groupname in groups:
        grouplist += groupname['email']+' '
      if grouplist[-1:] == ' ':
        grouplist = grouplist[:-1]
      user.update(Groups=grouplist)
      user_count += 1
  output_csv(user_attributes, titles, 'Users', todrive)

def doPrintGroups():
  i = 3
  printname = printdesc = printid = members = owners = managers = settings = admin_created = aliases = todrive = False
  usedomain = usemember = None
  group_attributes = [{'Email': 'Email'}]
  titles = ['Email']
  fields = 'nextPageToken,groups(email)'
  while i < len(argv):
    if argv[i].lower() == 'domain':
      usedomain = argv[i+1].lower()
      i += 2
    elif argv[i].lower() == 'todrive':
      todrive = True
      i += 1
    elif argv[i].lower() == 'member':
      usemember = argv[i+1].lower()
      i += 2
    elif argv[i].lower() == 'name':
      fields += ',groups(name)'
      printname = True
      group_attributes[0].update(Name='Name')
      titles.append('Name')
      i += 1
    elif argv[i].lower() == 'admincreated':
      fields += ',groups(adminCreated)'
      admin_created = True
      group_attributes[0].update(Admin_Created='Admin_Created')
      titles.append('Admin_Created')
      i += 1
    elif argv[i].lower() == 'description':
      fields += ',groups(description)'
      group_attributes[0].update(Description='Description')
      titles.append('Description')
      printdesc = True
      i += 1
    elif argv[i].lower() == 'id':
      fields += ',groups(id)'
      group_attributes[0].update(ID='ID')
      titles.append('ID')
      printid = True
      i += 1
    elif argv[i].lower() == 'aliases':
      fields += ',groups(aliases,nonEditableAliases)'
      group_attributes[0].update(Aliases='Aliases')
      group_attributes[0].update(NonEditableAliases='NonEditableAliases')
      titles.append('Aliases')
      titles.append('NonEditableAliases')
      aliases = True
      i += 1
    elif argv[i].lower() == 'members':
      group_attributes[0].update(Members='Members')
      titles.append('Members')
      members = True
      i += 1
    elif argv[i].lower() == 'owners':
      group_attributes[0].update(Owners='Owners')
      titles.append('Owners')
      owners = True
      i += 1
    elif argv[i].lower() == 'managers':
      group_attributes[0].update(Managers='Managers')
      titles.append('Managers')
      managers = True
      i += 1
    elif argv[i].lower() == 'settings':
      group_attributes[0].update(whoCanJoin='whoCanJoin')
      titles.append('whoCanJoin')
      group_attributes[0].update(membersCanPostAsTheGroup='membersCanPostAsTheGroup')
      titles.append('membersCanPostAsTheGroup')
      group_attributes[0].update(whoCanViewGroup='whoCanViewGroup')
      titles.append('whoCanViewGroup')
      group_attributes[0].update(whoCanViewMembership='whoCanViewMembership')
      titles.append('whoCanViewMembership')
      group_attributes[0].update(whoCanInvite='whoCanInvite')
      titles.append('whoCanInvite')
      group_attributes[0].update(allowExternalMembers='allowExternalMembers')
      titles.append('allowExternalMembers')
      group_attributes[0].update(whoCanPostMessage='whoCanPostMessage')
      titles.append('whoCanPostMessage')
      group_attributes[0].update(allowWebPosting='allowWebPosting')
      titles.append('allowWebPosting')
      group_attributes[0].update(maxMessageBytes='maxMessageBytes')
      titles.append('maxMessageBytes')
      group_attributes[0].update(isArchived='isArchived')
      titles.append('isArchived')
      group_attributes[0].update(archiveOnly='archiveOnly')
      titles.append('archiveOnly')
      group_attributes[0].update(messageModerationLevel='messageModerationLevel')
      titles.append('messageModerationLevel')
      group_attributes[0].update(primaryLanguage='primaryLanguage')
      titles.append('primaryLanguage')
      group_attributes[0].update(replyTo='replyTo')
      titles.append('replyTo')
      group_attributes[0].update(customReplyTo='customReplyTo')
      titles.append('customReplyTo')
      group_attributes[0].update(sendMessageDenyNotification='sendMessageDenyNotification')
      titles.append('sendMessageDenyNotification')
      group_attributes[0].update(defaultMessageDenyNotificationText='defaultMessageDenyNotificationText')
      titles.append('defaultMessageDenyNotificationText')
      group_attributes[0].update(showInGroupDirectory='showInGroupDirectory')
      titles.append('showInGroupDirectory')
      group_attributes[0].update(allowGoogleCommunication='allowGoogleCommunication')
      titles.append('allowGoogleCommunication')
      group_attributes[0].update(membersCanPostAsTheGroup='membersCanPostAsTheGroup')
      titles.append('members_CanPostAsTheGroup')
      group_attributes[0].update(messageDisplayFont='messageDisplayFont')
      titles.append('messageDisplayFont')
      group_attributes[0].update(includeInGlobalAddressList='includeInGlobalAddressList')
      titles.append('includeInGlobalAddressList')
      group_attributes[0].update(spamModerationLevel='spamModerationLevel')
      titles.append('spamModerationLevel')
      settings = True
      i += 1
    else:
      showUsage()
      return 7
  directoryObj = buildGAPIObject('directory')
  global customerId
  if usedomain or usemember:
    customerId = None
  sys.stderr.write("Retrieving All Groups for Google Apps account (may take some time on a large account)...\n")
  page_message = 'Got %%num_items%% groups: %%first_item%% - %%last_item%%\n'
  all_groups = callGAPIpages(service=directoryObj.groups(), function='list', items='groups', page_message=page_message, message_attribute='email', customer=customerId, domain=usedomain, fields=fields)
  total_groups = len(all_groups)
  count = 0
  for group_vals in all_groups:
    count += 1
    group = {}
    group.update({'Email': group_vals['email']})
    if printname:
      try:
        group.update({'Name': group_vals['name']})
      except KeyError:
        pass
    if printdesc:
      try:
        group.update({'Description': group_vals['description']})
      except KeyError:
        pass
    if printid:
      try:
        group.update({'ID': group_vals['id']})
      except KeyError:
        pass
    if admin_created:
      try:
        group.update({'Admin_Created': group_vals['adminCreated']})
      except KeyError:
        pass
    if aliases:
      try:
        group.update({'Aliases': ' '.join(group_vals['aliases'])})
        for alias in group_vals['aliases']:
          print '%s,%s' % (group_vals['email'].lower(), alias.lower())
      except KeyError:
        pass
      try:
        group.update({'NonEditableAliases': ' '.join(group_vals['nonEditableAliases'])})
      except KeyError:
        pass
    if members or owners or managers:
      roles = list()
      if members:
        roles.append('members')
      if owners:
        roles.append('owners')
      if managers:
        roles.append('managers')
      roles = ','.join(roles)
      sys.stderr.write(' Getting %s for %s (%s of %s)\n' % (roles, group_vals['email'], count, total_groups))
      page_message = 'Got %%num_items%% members: %%first_item%% - %%last_item%%\n'
      all_group_members = callGAPIpages(service=directoryObj.members(), function='list', items='members', page_message=page_message, message_attribute='email', groupKey=group_vals['email'], roles=roles, fields='nextPageToken,members(email,role)')
      if members:
        all_true_members = list()
      if managers:
        all_managers = list()
      if owners:
        all_owners = list()
      for member in all_group_members:
       try:
         member_email = member['email']
       except KeyError:
         sys.stderr.write(' Not sure to do with: %s' % member)
         continue
       try:
         if members and member['role'] == 'MEMBER':
           all_true_members.append(member_email)
         elif managers and member['role'] == 'MANAGER':
           all_managers.append(member_email)
         elif owners and member['role'] == 'OWNER':
           all_owners.append(member_email)
       except KeyError:
         all_true_members.append(member_email)
      if members:
        group.update({'Members': "\n".join(all_true_members)})
      if managers:
        group.update({'Managers': "\n".join(all_managers)})
      if owners:
        group.update({'Owners': "\n".join(all_owners)})
    if settings:
      sys.stderr.write(" Retrieving Settings for group %s (%s of %s)...\r\n" % (group_vals['email'], count, total_groups))
      groupssettingsObj = buildGAPIObject('groupssettings')
      settings = callGAPI(service=groupssettingsObj.groups(), function='get', groupUniqueId=group_vals['email'])
      for key in settings.keys():
        if key in ['email', 'name', 'description', 'kind']:
          continue
        setting_value = settings[key]
        if setting_value == None:
          setting_value = ''
        group.update({key: setting_value})
    group_attributes.append(group)
  output_csv(group_attributes, titles, 'Groups', todrive)

def doPrintOrgs():
  i = 3
  printname = printdesc = printparent = printinherit = todrive = False
  type = 'all'
  orgUnitPath = "/"
  org_attributes = []
  org_attributes.append({'Path': 'Path'})
  fields = 'organizationUnits(orgUnitPath)'
  titles = ['Path']
  while i < len(argv):
    if argv[i].lower() == 'name':
      printname = True
      org_attributes[0].update(Name='Name')
      fields += ',organizationUnits(name)'
      titles.append('Name')
      i += 1
    elif argv[i].lower() == 'toplevelonly':
      type = 'children'
      i += 1
    elif argv[i].lower() == 'parent':
      orgUnitPath = argv[i+1]
      i += 2
    elif argv[i].lower() == 'todrive':
      todrive = True
      i += 1
    elif argv[i].lower() == 'description':
      printdesc = True
      fields += ',organizationUnits(description)'
      org_attributes[0].update(Description='Description')
      titles.append('Description')
      i += 1
    elif argv[i].lower() == 'parent':
      printparent = True
      fields += ',organizationUnits(parentOrgUnitPath)'
      org_attributes[0].update(Parent='Parent')
      titles.append('Parent')
      i += 1
    elif argv[i].lower() == 'inherit':
      printinherit = True
      fields += ',organizationUnits(blockInheritance)'
      org_attributes[0].update(InheritanceBlocked='InheritanceBlocked')
      titles.append('InheritanceBlocked')
      i += 1
    else:
      showUsage()
      exit(8)
  directoryObj = buildGAPIObject('directory')
  sys.stderr.write("Retrieving All Organizational Units for your account (may take some time on large domain)...")
  orgs = callGAPI(service=directoryObj.orgunits(), function='list', customerId=customerId, fields=fields, type=type, orgUnitPath=orgUnitPath)
  sys.stderr.write("done\n")
  for org_vals in orgs['organizationUnits']:
    orgUnit = {}
    orgUnit.update({'Path': org_vals['orgUnitPath']})
    if printname:
      name = org_vals['name']
      if name == None:
        name = ''
      orgUnit.update({'Name': name})
    if printdesc:
      try:
        desc = org_vals['description']
        if desc == None:
          desc = ''
      except KeyError:
        pass
      orgUnit.update({'Description': desc})
    if printparent:
      parent = org_vals['parentOrgUnitPath']
      if parent == None:
        parent = ''
      orgUnit.update({'Parent': parent})
    if printinherit:
      try:
        orgUnit.update({'InheritanceBlocked': org_vals['blockInheritance']})
      except KeyError:
        pass
    org_attributes.append(orgUnit)
  output_csv(org_attributes, titles, 'Orgs', todrive)

def doPrintAliases():
  todrive = False
  i = 3
  while i < len(argv):
    if argv[i].lower() == 'todrive':
      todrive = True
    i += 1
  directoryObj = buildGAPIObject('directory')
  alias_attributes = []
  alias_attributes.append({'Alias': 'Alias'})
  alias_attributes[0].update(Target='Target')
  alias_attributes[0].update(TargetType='TargetType')
  titles = ['Alias', 'Target', 'TargetType']
  sys.stderr.write("Retrieving All User Aliases for %s organization (may take some time on large domain)...\n" % domain)
  page_message = 'Got %%num_items%% users %%first_item%% - %%last_item%%\n'
  all_users = callGAPIpages(service=directoryObj.users(), function='list', items='users', page_message=page_message, message_attribute='primaryEmail', customer=customerId, fields='users(primaryEmail,aliases),nextPageToken', maxResults=500)
  for user in all_users:
    try:
      for alias in user['aliases']:
        alias_attributes.append({'Alias': alias, 'Target': user['primaryEmail'], 'TargetType': 'User'})
    except KeyError:
      continue
  sys.stderr.write("Retrieving All User Aliases for %s organization (may take some time on large domain)...\n" % domain)
  page_message = 'Got %%num_items%% groups %%first_item%% - %%last_item%%\n'
  all_groups = callGAPIpages(service=directoryObj.groups(), function='list', items='groups', page_message=page_message, message_attribute='email', customer=customerId, fields='groups(email,aliases),nextPageToken')
  for group in all_groups:
    try:
      for alias in group['aliases']:
        alias_attributes.append({'Alias': alias, 'Target': group['email'], 'TargetType': 'Group'})
    except KeyError:
      continue
  output_csv(alias_attributes, titles, 'Aliases', todrive)

def doPrintGroupMembers():
  todrive = False
  i = 3
  while i < len(argv):
    if argv[i].lower() == 'todrive':
      todrive = True
    i += 1
  directoryObj = buildGAPIObject('directory')
  member_attributes = [{'group': 'group'},]
  all_groups = callGAPIpages(service=directoryObj.groups(), function='list', items='groups', message_attribute='email', customer=customerId, fields='nextPageToken,groups(email)')
  total_groups = len(all_groups)
  i = 1
  for group in all_groups:
    group_email = group['email']
    sys.stderr.write('Getting members for %s (%s/%s)\n' % (group_email, i, total_groups))
    group_members = callGAPIpages(service=directoryObj.members(), function='list', items='members', message_attribute='email', groupKey=group_email)
    for member in group_members:
      member_attr = {'group': group_email}
      for title in member.keys():
        if title in ['kind',]:
          continue
        try:
          member_attributes[0][title]
          member_attr[title] = member[title]
        except KeyError:
          member_attributes[0][title] = title
          member_attr[title] = member[title]
      member_attributes.append(member_attr)
    i += 1
  titles = member_attributes[0].keys()
  output_csv(member_attributes, titles, 'Group Members', todrive)

def doPrintMobileDevices():
  directoryObj = buildGAPIObject('directory')
  mobile_attributes = [{}]
  titles = []
  todrive = False
  query = orderBy = sortOrder = None
  i = 3
  while i < len(argv):
    if argv[i].lower() == 'query':
      query = argv[i+1]
      i += 2
    elif argv[i].lower() == 'todrive':
      todrive = True
      i += 1
    elif argv[i].lower() == 'orderby':
      orderBy = argv[i+1].lower()
      allowed_values = ['deviceid', 'email', 'lastsync', 'model', 'name', 'os', 'status', 'type']
      if orderBy.lower() not in allowed_values:
        print 'Error: orderBy must be one of %s. Got %s' % (', '.join(allowed_values), orderBy)
        return 3
      elif orderBy == 'lastsync':
        orderBy = 'lastSync'
      i += 2
    elif argv[i].lower() in ['ascending', 'descending']:
      sortOrder = argv[i].upper()
      i += 1
  sys.stderr.write('Retrieving All Mobile Devices for organization (may take some time for large accounts)...\n')
  page_message = 'Got %%num_items%% mobile devices...\n'
  all_mobile = callGAPIpages(service=directoryObj.mobiledevices(), function='list', items='mobiledevices', page_message=page_message, customerId=customerId, query=query, orderBy=orderBy, sortOrder=sortOrder)
  for mobile in all_mobile:
    mobiledevice = dict()
    for title in mobile.keys():
      try:
        if title in ['kind','applications']:
          continue
        try:
          mobile_attributes[0][title]
        except KeyError:
          mobile_attributes[0][title] = title
          titles.append(title)
        if title == 'name' or title == 'email':
          mobiledevice[title] = mobile[title][0]
        else:
          mobiledevice[title] = mobile[title]
      except KeyError:
        pass
    mobile_attributes.append(mobiledevice)
  output_csv(mobile_attributes, titles, 'Mobile', todrive)

def doPrintCrosDevices():
  directoryObj = buildGAPIObject('directory')
  cros_attributes = [{}]
  titles = []
  todrive = False
  query = orderBy = sortOrder = None
  i = 3
  while i < len(argv):
    if argv[i].lower() == 'query':
      query = argv[i+1]
      i += 2
    elif argv[i].lower() == 'todrive':
      todrive = True
      i += 1
    elif argv[i].lower() == 'orderby':
      orderBy = argv[i+1].lower()
      allowed_values = ['location', 'user', 'lastsync', 'notes', 'serialnumber', 'status', 'supportenddate']
      if orderBy.lower() not in allowed_values:
        print 'Error: orderBy must be one of %s. Got %s' % (', '.join(allowed_values), orderBy)
        return 3
      elif orderBy == 'location':
        orderBy = 'annotatedLocation'
      elif orderBy == 'user':
        orderBy = 'annotatedUser'
      elif orderBy == 'lastsync':
        orderBy == 'lastSync'
      elif orderBy == 'serialnumber':
        orderBy = 'serialNumber'
      elif orderBy == 'supportEndDate':
        orderBy = 'supportEndDate'
      i += 2
    elif argv[i].lower() in ['ascending', 'descending']:
      sortOrder = argv[i].upper()
      i += 1
  sys.stderr.write('Retrieving All Chrome OS Devices for organization (may take some time for large accounts)...\n')
  page_message = 'Got %%num_items%% Chrome devices...\n'
  all_cros = callGAPIpages(service=directoryObj.chromeosdevices(), function='list', items='chromeosdevices', page_message=page_message, query=query, customerId=customerId, sortOrder=sortOrder)
  for cros in all_cros:
    crosdevice = dict()
    for title in cros.keys():
      if title in ['kind']:
        continue
      try:
        cros_attributes[0][title]
      except KeyError:
        cros_attributes[0][title] = title
        titles.append(title)
      crosdevice[title] = cros[title]
    cros_attributes.append(crosdevice)
  output_csv(cros_attributes, titles, 'CrOS', todrive)

def doPrintLicenses():
  licensingObj = buildGAPIObject('licensing')
  products = ['Google-Apps', 'Google-Drive-storage', 'Google-Coordinate', 'Google-Vault']
  lic_attributes = [{}]
  todrive = False
  i = 3
  while i < len(argv):
    if argv[i].lower() == 'todrive':
      todrive = True
      i += 1
    else:
      print 'Error: %s is not a valid argument to gam print licenses' % argv[i]
      return 3
  for productId in products:
    page_message = 'Got %%%%total_items%%%% Licenses for %s...\n' % productId
    try:
      licenses = callGAPIpages(service=licensingObj.licenseAssignments(), function='listForProduct', items='items', throw_reasons=['invalid'], page_message=page_message, customerId=domain, productId=productId, maxResults=1000)
    except apiclient.errors.HttpError:
      licenses = [] 
    for license in licenses:
      a_license = dict()
      for title in license.keys():
        if title in ['kind', 'etags', 'selfLink']:
          continue
        if title not in lic_attributes[0]:
          lic_attributes[0][title] = title
        a_license[title] = license[title]
      lic_attributes.append(a_license)
  output_csv(lic_attributes, lic_attributes[0], 'Licenses', todrive)

def doPrintResources():
  i = 3
  res_attributes = []
  res_attributes.append({'Name': 'Name'})
  titles = ['Name']
  printid = printdesc = printemail = todrive = False
  while i < len(argv):
    if argv[i].lower() == 'allfields':
      printid = printdesc = printemail = True
      res_attributes[0].update(ID='ID', Description='Description', Email='Email')
      titles.append('ID')
      titles.append('Description')
      titles.append('Email')
      i += 1
    elif argv[i].lower() == 'todrive':
      todrive = True
      i += 1
    elif argv[i].lower() == 'id':
      printid = True
      res_attributes[0].update(ID='ID')
      titles.append('ID')
      i += 1
    elif argv[i].lower() == 'description':
      printdesc = True
      res_attributes[0].update(Description='Description')
      titles.append('Description')
      i += 1
    elif argv[i].lower() == 'email':
      printemail = True
      res_attributes[0].update(Email='Email')
      titles.append('Email')
      i += 1
    else:
      showUsage()
      return 2
  resObj = getResCalObject()
  sys.stderr.write("Retrieving All Resource Calendars for your account (may take some time on a large domain)")
  resources = callGData(service=resObj, function='RetrieveAllResourceCalendars')
  for resource in resources:
    resUnit = {}
    resUnit.update({'Name': resource['resourceCommonName']})
    if printid:
      resUnit.update({'ID': resource['resourceId']})
    if printdesc:
      try:
        desc = resource['resourceDescription']
      except KeyError:
        desc = ''
      resUnit.update({'Description': desc})
    if printemail:
      resUnit.update({'Email': resource['resourceEmail']})
    res_attributes.append(resUnit)
  output_csv(res_attributes, titles, 'Resources', todrive)

def doCreateMonitor():
  source_user = argv[4].lower()
  destination_user = argv[5].lower()
  #end_date defaults to 30 days in the future...
  end_date = (datetime.datetime.now() + datetime.timedelta(days=30)).strftime("%Y-%m-%d %H:%M")
  begin_date = None
  incoming_headers_only = outgoing_headers_only = drafts_headers_only = chats_headers_only = False
  drafts = chats = True
  i = 6
  while i < len(argv):
    if argv[i].lower() == 'end':
      end_date = argv[i+1]
      i += 2
    elif argv[i].lower() == 'begin':
      begin_date = argv[i+1]
      i += 2
    elif argv[i].lower() == 'incoming_headers':
      incoming_headers_only = True
      i += 1
    elif argv[i].lower() == 'outgoing_headers':
      outgoing_headers_only = True
      i += 1
    elif argv[i].lower() == 'nochats':
      chats = False
      i += 1
    elif argv[i].lower() == 'nodrafts':
      drafts = False
      i += 1
    elif argv[i].lower() == 'chat_headers':
      chats_headers_only = True
      i += 1
    elif argv[i].lower() == 'draft_headers':
      drafts_headers_only = True
      i += 1
    else:
      showUsage()
      return 2
  audit = getAuditObject()
  if source_user.find('@') > 0:
    audit.domain = source_user[source_user.find('@')+1:]
    source_user = source_user[:source_user.find('@')]
  callGData(service=audit, function='createEmailMonitor', source_user=source_user, destination_user=destination_user, end_date=end_date, begin_date=begin_date,
                           incoming_headers_only=incoming_headers_only, outgoing_headers_only=outgoing_headers_only,
                           drafts=drafts, drafts_headers_only=drafts_headers_only, chats=chats, chats_headers_only=chats_headers_only)

def doShowMonitors():
  user = argv[4].lower()
  audit = getAuditObject()
  if user.find('@') > 0:
    audit.domain = user[user.find('@')+1:]
    user = user[:user.find('@')]
  results = callGData(service=audit, function='getEmailMonitors', user=user)
  print argv[4].lower()+' has the following monitors:'
  print ''
  for monitor in results:
    print ' Destination: '+monitor['destUserName']
    try:
      print '  Begin: '+monitor['beginDate']
    except KeyError:
      print '  Begin: immediately'
    print '  End: '+monitor['endDate']
    print '  Monitor Incoming: '+monitor['outgoingEmailMonitorLevel']
    print '  Monitor Outgoing: '+monitor['incomingEmailMonitorLevel']
    print '  Monitor Chats: '+monitor['chatMonitorLevel']
    print '  Monitor Drafts: '+monitor['draftMonitorLevel']
    print ''

def doDeleteMonitor():
  source_user = argv[4].lower()
  destination_user = argv[5].lower()
  audit = getAuditObject()
  if source_user.find('@') > 0:
    audit.domain = source_user[source_user.find('@')+1:]
    source_user = source_user[:source_user.find('@')]
  callGData(service=audit, function='deleteEmailMonitor', source_user=source_user, destination_user=destination_user)

def doRequestActivity():
  user = argv[4].lower()
  audit = getAuditObject()
  if user.find('@') > 0:
    audit.domain = user[user.find('@')+1:]
    user = user[:user.find('@')]
  results = callGData(service=audit, function='createAccountInformationRequest', user=user)
  print 'Request successfully submitted:'
  print ' Request ID: '+results['requestId']
  print ' User: '+results['userEmailAddress']
  print ' Status: '+results['status']
  print ' Request Date: '+results['requestDate']
  print ' Requested By: '+results['adminEmailAddress']

def doStatusActivityRequests():
  audit = getAuditObject()
  try:
    user = argv[4].lower()
    if user.find('@') > 0:
      audit.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    request_id = argv[5].lower()
    results = callGData(service=audit, function='getAccountInformationRequestStatus', user=user, request_id=request_id)
    print ''
    print '  Request ID: '+results['requestId']
    print '  User: '+results['userEmailAddress']
    print '  Status: '+results['status']
    print '  Request Date: '+results['requestDate']
    print '  Requested By: '+results['adminEmailAddress']
    try:
      print '  Number Of Files: '+results['numberOfFiles']
      for i in range(int(results['numberOfFiles'])):
        print '  Url%s: %s' % (i, results['fileUrl%s' % i])
    except KeyError:
      pass
    print ''
  except IndexError:
    results = callGData(service=audit, function='getAllAccountInformationRequestsStatus')
    print 'Current Activity Requests:'
    print ''
    for request in results:
      print ' Request ID: '+request['requestId']
      print '  User: '+request['userEmailAddress']
      print '  Status: '+request['status']
      print '  Request Date: '+request['requestDate']
      print '  Requested By: '+request['adminEmailAddress']
      try:
        print '  Number Of Files: '+request['numberOfFiles']
        for i in range(int(request['numberOfFiles'])):
          print '  Url%s: %s' % (i, request['fileUrl%s' % i])
      except KeyError:
        pass
      print ''

def doDownloadActivityRequest():
  user = argv[4].lower()
  request_id = argv[5].lower()
  audit = getAuditObject()
  if user.find('@') > 0:
    audit.domain = user[user.find('@')+1:]
    user = user[:user.find('@')]
  results = callGData(service=audit, function='getAccountInformationRequestStatus', user=user, request_id=request_id)
  if results['status'] != 'COMPLETED':
    print 'Request needs to be completed before downloading, current status is: '+results['status']
    return 4
  try:
    if int(results['numberOfFiles']) < 1:
      print 'ERROR: Request completed but no results were returned, try requesting again'
      return 4
  except KeyError:
    print 'ERROR: Request completed but no files were returned, try requesting again'
    return 4
  for i in range(0, int(results['numberOfFiles'])):
    url = results['fileUrl'+str(i)]
    filename = 'activity-'+user+'-'+request_id+'-'+str(i)+'.txt.gpg'
    print 'Downloading '+filename+' ('+str(i+1)+' of '+results['numberOfFiles']+')'
    geturl(url, filename)

def doRequestExport():
  begin_date = end_date = search_query = None
  headers_only = include_deleted = False
  user = argv[4].lower()
  i = 5
  while i < len(argv):
    if argv[i].lower() == 'begin':
      begin_date = argv[i+1]
      i += 2
    elif argv[i].lower() == 'end':
      end_date = argv[i+1]
      i += 2
    elif argv[i].lower() == 'search':
      search_query = argv[i+1]
      i += 2
    elif argv[i].lower() == 'headersonly':
      headers_only = True
      i += 1
    elif argv[i].lower() == 'includedeleted':
      include_deleted = True
      i += 1
    else:
      showUsage()
      return 2
  audit = getAuditObject()
  if user.find('@') > 0:
    audit.domain = user[user.find('@')+1:]
    user = user[:user.find('@')]
  results = callGData(service=audit, function='createMailboxExportRequest', user=user, begin_date=begin_date, end_date=end_date, include_deleted=include_deleted,
                                             search_query=search_query, headers_only=headers_only)
  print 'Export request successfully submitted:'
  print ' Request ID: '+results['requestId']
  print ' User: '+results['userEmailAddress']
  print ' Status: '+results['status']
  print ' Request Date: '+results['requestDate']
  print ' Requested By: '+results['adminEmailAddress']
  print ' Include Deleted: '+results['includeDeleted']
  print ' Requested Parts: '+results['packageContent']
  try:
    print ' Begin: '+results['beginDate']
  except KeyError:
    print ' Begin: account creation date'
  try:
    print ' End: '+results['endDate']
  except KeyError:
    print ' End: export request date'

def doDeleteExport():
  audit = getAuditObject()
  user = argv[4].lower()
  if user.find('@') > 0:
    audit.domain = user[user.find('@')+1:]
    user = user[:user.find('@')]
  request_id = argv[5].lower()
  results = callGData(service=audit, function='deleteMailboxExportRequest', user=user, request_id=request_id)

def doDeleteActivityRequest():
  audit = getAuditObject()
  user = argv[4].lower()
  if user.find('@') > 0:
    audit.domain = user[user.find('@')+1:]
    user = user[:user.find('@')]
  request_id = argv[5].lower()
  callGData(service=audit, function='deleteAccountInformationRequest', user=user, request_id=request_id)

def doStatusExportRequests():
  audit = getAuditObject()
  try:
    user = argv[4].lower()
    if user.find('@') > 0:
      audit.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    request_id = argv[5].lower()
    results = callGData(service=audit, function='getMailboxExportRequestStatus', user=user, request_id=request_id)
    print ''
    print '  Request ID: '+results['requestId']
    print '  User: '+results['userEmailAddress']
    print '  Status: '+results['status']
    print '  Request Date: '+results['requestDate']
    print '  Requested By: '+results['adminEmailAddress']
    print '  Requested Parts: '+results['packageContent']
    try:
      print '  Request Filter: '+results['searchQuery']
    except KeyError:
      print '  Request Filter: None'
    print '  Include Deleted: '+results['includeDeleted']
    try:
      print '  Number Of Files: '+results['numberOfFiles']
      for i in range(int(results['numberOfFiles'])):
        print '  Url%s: %s' % (i, results['fileUrl%s' % i])
    except KeyError:
      pass
  except IndexError:
    results = callGData(service=audit, function='getAllMailboxExportRequestsStatus')
    print 'Current Export Requests:'
    print ''
    for request in results:
      print ' Request ID: '+request['requestId']
      print '  User: '+request['userEmailAddress']
      print '  Status: '+request['status']
      print '  Request Date: '+request['requestDate']
      print '  Requested By: '+request['adminEmailAddress']
      print '  Requested Parts: '+request['packageContent']
      try:
        print '  Request Filter: '+request['searchQuery']
      except KeyError:
        print '  Request Filter: None'
      print '  Include Deleted: '+request['includeDeleted']
      try:
        print '  Number Of Files: '+request['numberOfFiles']
      except KeyError:
        pass
      print ''

def doDownloadExportRequest():
  user = argv[4].lower()
  request_id = argv[5].lower()
  audit = getAuditObject()
  if user.find('@') > 0:
    audit.domain = user[user.find('@')+1:]
    user = user[:user.find('@')]
  results = callGData(service=audit, function='getMailboxExportRequestStatus', user=user, request_id=request_id)
  if results['status'] != 'COMPLETED':
    print 'Request needs to be completed before downloading, current status is: '+results['status']
    return 4
  try:
    if int(results['numberOfFiles']) < 1:
      print 'ERROR: Request completed but no results were returned, try requesting again'
      return 4
  except KeyError:
    print 'ERROR: Request completed but no files were returned, try requesting again'
    return 4
  for i in range(0, int(results['numberOfFiles'])):
    url = results['fileUrl'+str(i)]
    filename = 'export-'+user+'-'+request_id+'-'+str(i)+'.mbox.gpg'
    #don't download existing files. This does not check validity of existing local
    #file so partial/corrupt downloads will need to be deleted manually.
    if os.path.isfile(filename):
      continue
    print 'Downloading '+filename+' ('+str(i+1)+' of '+results['numberOfFiles']+')'
    geturl(url, filename)

def doUploadAuditKey():
  auditkey = sys.stdin.read()
  audit = getAuditObject()
  results = callGData(service=audit, function='updatePGPKey', pgpkey=auditkey)
  print results

def getUsersToModify(entity_type=None, entity=None, silent=False):
  global domain, customerId
  directoryObj = buildGAPIObject('directory')
  if entity_type == None:
    entity_type = argv[1].lower()
  if entity == None:
    entity = argv[2].lower()
  if entity_type == 'user':
    users = [entity,]
  elif entity_type == 'users':
    if entity.find(' ') != -1:
      users = entity.split(' ')
    else:
      users = entity.split(',')
  elif entity_type == 'group':
    group = entity
    if group.find('@') == -1:
      group = '%s@%s' % (group, domain)
    page_message = None
    if not silent:
      sys.stderr.write("Getting all members of %s (may take some time for large groups)..." % group)
      page_message = 'Got %%total_items%% members...\n'
    members = callGAPIpages(service=directoryObj.members(), function='list', items='members', page_message=page_message, groupKey=group, fields='nextPageToken,members(email)')
    users = []
    for member in members:
      users.append(member['email'])
  elif entity_type in ['ou', 'org']:
    ou = entity
    if ou[0] != '/':
      ou = '/%s' % ou
    users = []
    if not silent: sys.stderr.write("Getting all users in the Google Apps organization (may take some time on a large domain)...\n")
    page_message = 'Got %%num_items%% users\n'
    members = callGAPIpages(service=directoryObj.users(), function='list', items='users', page_message=page_message, customer=customerId, fields='nextPageToken,users(primaryEmail,orgUnitPath)', maxResults=500)
    for member in members:
      if member['orgUnitPath'].lower() == ou.lower():
        users.append(member['primaryEmail'])
    if not silent: sys.stderr.write("done.\r\n")
  elif entity_type == 'file':
    users = []
    filename = entity
    usernames = csv.reader(open(filename, 'rb'))
    for row in usernames:
      try:
        users.append(row.pop())
      except IndexError:
        pass
  elif entity_type == 'all':
    directoryObj = buildGAPIObject('directory')
    users = []
    if entity == 'users':
      if not silent: sys.stderr.write("Getting all users in Google Apps account (may take some time on a large account)...\n")
      page_message = 'Got %%num_items%% users\n'
      all_users = callGAPIpages(service=directoryObj.users(), function='list', items='users', page_message=page_message, customer=customerId, fields='nextPageToken,users(primaryEmail,suspended)', maxResults=500)
      for member in all_users:
        if member['suspended'] == False:
          users.append(member['primaryEmail'])
      if not silent: sys.stderr.write("done getting %s users.\r\n" % len(users))
    elif entity == 'cros':
      if not silent: sys.stderr.write("Getting all CrOS devices in Google Apps account (may take some time on a large account)...\n")
      all_cros = callGAPIpages(service=directoryObj.chromeosdevices(), function='list', items='chromeosdevices', customerId=customerId, fields='nextPageToken,chromeosdevices(deviceId)')
      for member in all_cros:
        users.append(member['deviceId'])
      if not silent: sys.stderr.write("done getting %s CrOS devices.\r\n" % len(users))
  else:
    showUsage()
    return 2
  full_users = list()
  if entity != 'cros':
    for user in users:
      if user.find('@') == -1:
        full_users.append('%s@%s' % (user, domain))
      else:
        full_users.append(user)
  return full_users

def OAuthInfo():
  oauth2file = getGamPath()+'oauth2.txt'
  try:
    oauth2file = getGamPath()+os.environ['OAUTHFILE']
  except KeyError:
    pass
  storage = oauth2client.file.Storage(oauth2file)
  credentials = storage.get()
  if credentials is None or credentials.invalid:
    doRequestOAuth()
    credentials = storage.get()
  domain = credentials.id_token['hd']
  credentials.user_agent = 'Dito GAM %s / %s / Python %s.%s.%s %s / %s %s /' % (__version__, __author__,
                   sys.version_info[0], sys.version_info[1], sys.version_info[2],
                   sys.version_info[3], platform.platform(), platform.machine())
  disable_ssl_certificate_validation = False
  if os.path.isfile(getGamPath()+'noverifyssl.txt'):
    disable_ssl_certificate_validation = True
  http = httplib2.Http(ca_certs=getGamPath()+'cacert.pem', disable_ssl_certificate_validation=disable_ssl_certificate_validation)
  if os.path.isfile(getGamPath()+'debug.gam'):
    httplib2.debuglevel = 4
  if credentials.access_token_expired:
    credentials.refresh(http)
  print "\nOAuth File: %s" % oauth2file
  if os.path.isfile(oauth2file):
    oauth2Obj = buildGAPIObject('oauth2')
    token_info = callGAPI(service=oauth2Obj, function='tokeninfo', access_token=credentials.access_token)
    print "Client ID: %s\nSecret: %s" % (credentials.client_id, credentials.client_secret)
    print 'Scopes:'
    for scope in token_info['scope'].split(' '):
      print '  %s' % scope
    print 'Google Apps Admin: %s' % token_info['email']
  else:
    print 'Error: That OAuth file doesn\'t exist!'

def doDeleteOAuth():
  oauth2file = getGamPath()+'oauth2.txt'
  try:
    oauth2file = getGamPath()+os.environ['OAUTHFILE']
  except KeyError:
    pass
  storage = oauth2client.file.Storage(oauth2file)
  credentials = storage.get()
  try:
    credentials.revoke_uri = oauth2client.GOOGLE_REVOKE_URI
  except AttributeError:
    print 'Error: Authorization doesn\'t exist'
    return 1
  certFile = getGamPath()+'cacert.pem'
  disable_ssl_certificate_validation = False
  if os.path.isfile(getGamPath()+'noverifyssl.txt'):
    disable_ssl_certificate_validation = True
  http = httplib2.Http(ca_certs=certFile, disable_ssl_certificate_validation=disable_ssl_certificate_validation)
  if os.path.isfile(getGamPath()+'debug.gam'):
    httplib2.debuglevel = 4
  sys.stderr.write('This OAuth token will self-destruct in 3...')
  time.sleep(1)
  sys.stderr.write('2...')
  time.sleep(1)
  sys.stderr.write('1...')
  time.sleep(1)
  sys.stderr.write('boom!\n')
  try:
    credentials.revoke(http)
  except oauth2client.client.TokenRevokeError, e:
    print 'Error: %s' % e
    return 1 

class cmd_flags(object):
  def __init__(self):
    self.short_url = True 
    self.noauth_local_webserver = False
    self.logging_level = 'ERROR' 
    self.auth_host_name = 'localhost'
    self.auth_host_port = [8080, 9090]

def doRequestOAuth():
  if not os.path.isfile(getGamPath()+'nodito.txt'):
    print "\n\nGAM is made possible and maintained by the work of Dito. Who is Dito?\n\nDito is solely focused on moving organizations to Google's cloud.  After hundreds of successful deployments over the last 5 years, we have gained notoriety for our complete understanding of the platform, our change management & training ability, and our rock-star deployment engineers.  We are known worldwide as the Google Apps Experts.\n"
    visit_dito = raw_input("Want to learn more about Dito? Hit Y to visit our website (you can switch back to this window when you're done). Hit Enter to continue without visiting Dito: ")
    if visit_dito.lower() == 'y':
      import webbrowser
      webbrowser.open('http://www.ditoweb.com?s=gam')
  CLIENT_SECRETS = getGamPath()+'client_secrets.json'
  MISSING_CLIENT_SECRETS_MESSAGE = """
WARNING: Please configure OAuth 2.0

To make GAM run you will need to populate the client_secrets.json file
found at:

   %s

instructions for doing so are at: http://goo.gl/QYaQ6R

""" % CLIENT_SECRETS

  selected_scopes = ['*', '*', '*', '*', '*', '*', '*', '*', '*', '*', '*', '*', '*', '*', '*']
  menu = '''Select the authorized scopes for this token. Include a 'r' to grant read-only
access or an 'a' to grant action-only access.

[%s]  0)  Group Directory API (supports read-only)
[%s]  1)  Organizational Unit Directory API (supports read-only)
[%s]  2)  User Directory API (supports read-only)
[%s]  3)  Chrome OS Device Directory API (supports read-only)
[%s]  4)  Mobile Device Directory API (supports read-only and action)
[%s]  5)  User Email Settings API
[%s]  6)  Calendar Resources API
[%s]  7)  Audit Monitors, Activity and Mailbox Exports API
[%s]  8)  Admin Settings API
[%s]  9)  Groups Settings API
[%s] 10)  Calendar Data API (supports read-only)
[%s] 11)  Audit Reports API
[%s] 12)  Usage Reports API
[%s] 13)  Drive API (create report documents for admin user only)
[%s] 14)  License Manager API

     15)  Select all scopes
     16)  Unselect all scopes
     17)  Continue
'''
  os.system(['clear','cls'][os.name == 'nt'])
  while True:
    selection = raw_input(menu % (selected_scopes[0], selected_scopes[1], selected_scopes[2], selected_scopes[3], selected_scopes[4], selected_scopes[5], selected_scopes[6], selected_scopes[7], selected_scopes[8], selected_scopes[9], selected_scopes[10], selected_scopes[11], selected_scopes[12], selected_scopes[13], selected_scopes[14]))
    try:
      if selection.lower().find('r') != -1:
        selection = int(selection.replace('r', ''))
        if selection not in [0, 1, 2, 3, 4, 10]:
          os.system(['clear', 'cls'][os.name == 'nt'])
          print 'THAT SCOPE DOES NOT SUPPORT READ-ONLY MODE!\n'
          continue
        selected_scopes[selection] = 'R'
      elif selection.lower().find('a') != -1:
        selection = int(selection.replace('a', ''))
        if selection not in [4,]:
          os.system(['clear', 'cls'][os.name == 'nt'])
          print 'THAT SCOPE DOES NOT SUPPORT ACTION-ONLY MODE!\n'
          continue
        selected_scopes[selection] = 'A'
      elif int(selection) > -1 and int(selection) < 15:
        if selected_scopes[int(selection)] == ' ':
          selected_scopes[int(selection)] = '*'
        else:
          selected_scopes[int(selection)] = ' '
      elif selection == '15':
        for i in range(0, len(selected_scopes)):
          selected_scopes[i] = '*'
      elif selection == '16':
        for i in range(0, len(selected_scopes)):
           selected_scopes[i] = ' '
      elif selection == '17':
        at_least_one = False
        for i in range(0, len(selected_scopes)):
          if selected_scopes[i] in ['*', 'R', 'A']:
            at_least_one = True
        if at_least_one:
          break
        else:
          os.system(['clear','cls'][os.name == 'nt'])
          print "YOU MUST SELECT AT LEAST ONE SCOPE!\n"
          continue
      else:
        os.system(['clear','cls'][os.name == 'nt'])
        print 'NOT A VALID SELECTION!'
        continue
      os.system(['clear','cls'][os.name == 'nt'])
    except ValueError:
      os.system(['clear','cls'][os.name == 'nt'])
      print 'Not a valid selection.'
      continue

  possible_scopes = ['https://www.googleapis.com/auth/admin.directory.group',            # Groups Directory Scope
                     'https://www.googleapis.com/auth/admin.directory.orgunit',          # Organization Directory Scope
                     'https://www.googleapis.com/auth/admin.directory.user',             # Users Directory Scope
                     'https://www.googleapis.com/auth/admin.directory.device.chromeos',  # Chrome OS Devices Directory Scope
                     'https://www.googleapis.com/auth/admin.directory.device.mobile',    # Mobile Device Directory Scope
                     'https://apps-apis.google.com/a/feeds/emailsettings/2.0/',          # Email Settings API
                     'https://apps-apis.google.com/a/feeds/calendar/resource/',          # Calendar Resource API
                     'https://apps-apis.google.com/a/feeds/compliance/audit/',           # Email Audit API
                     'https://apps-apis.google.com/a/feeds/domain/',                     # Admin Settings API
                     'https://www.googleapis.com/auth/apps.groups.settings',             # Group Settings API
                     'https://www.googleapis.com/auth/calendar',                         # Calendar Data API
                     'https://www.googleapis.com/auth/admin.reports.audit.readonly',     # Audit Reports
                     'https://www.googleapis.com/auth/admin.reports.usage.readonly',     # Usage Reports
                     'https://www.googleapis.com/auth/drive.file',                       # Drive API - Admin user access to files created or opened by the app
                     'https://www.googleapis.com/auth/apps.licensing']                   # License Manager API
  scopes = ['https://www.googleapis.com/auth/userinfo.email',]                           # Email Display Scope, always included
  for i in range(0, len(selected_scopes)):
    if selected_scopes[i] == '*':
      scopes.append(possible_scopes[i])
    elif selected_scopes[i] == 'R':
      scopes.append('%s.readonly' % possible_scopes[i])
    elif selected_scopes[i] == 'A':
      scopes.append('%s.action' % possible_scopes[i])
  FLOW = oauth2client.client.flow_from_clientsecrets(CLIENT_SECRETS,
    scope=scopes,
    message=MISSING_CLIENT_SECRETS_MESSAGE)
  oauth2file = getGamPath()+'oauth2.txt'
  try:
    oauth2file = getGamPath()+os.environ['OAUTHFILE']
  except KeyError:
    pass
  storage = oauth2client.file.Storage(oauth2file)
  credentials = storage.get()
  flags = cmd_flags()
  if os.path.isfile(getGamPath()+'nobrowser.txt'):
    flags.noauth_local_webserver = True
  if credentials is None or credentials.invalid:
    certFile = getGamPath()+'cacert.pem'
    disable_ssl_certificate_validation = False
    if os.path.isfile(getGamPath()+'noverifyssl.txt'):
      disable_ssl_certificate_validation = True
    http = httplib2.Http(ca_certs=certFile, disable_ssl_certificate_validation=disable_ssl_certificate_validation)
    try:
      credentials = oauth2client.tools.run_flow(flow=FLOW, storage=storage, flags=flags, http=http)
    except httplib2.CertificateValidationUnsupported:
      print '\nError: You don\'t have the Python ssl module installed so we can\'t verify SSL Certificates.\n\nYou can fix this by installing the Python SSL module or you can live on dangerously and turn SSL validation off by creating a file called noverifyssl.txt in the same location as gam.exe / gam.py'
      return 8

def main(is_batch=False):
  global argv, gam_batch
  try:
    if argv[1].lower() == 'batch':
      f = file(argv[2], 'rb')
      for line in f:
        import shlex
        argv = shlex.split(line)
        if argv[0] in ['#', ' ', ''] or len(argv) < 2:
          continue
        elif argv[0].lower() != 'gam':
          print 'Error: "%s" is not a valid gam command' % line
          continue
        main(is_batch=True)
    elif argv[1].lower() == 'csv':
      f = file(argv[2], 'rb')
      input_file = csv.DictReader(f)
      if argv[3].lower() != 'gam':
        print 'Error: "gam csv <filename>" should be followed by a full GAM command...'
        sys.exit(3)
      argv_template = argv[3:]
      for row in input_file:
        argv = list()
        for arg in argv_template:
          if arg[0] != '$':
            argv.append(arg)
          elif arg[1:] in row.keys():
            argv.append(row[arg[1:]])
          else:
            print 'Error: arg header "%s" not found in CSV, giving up.' % arg[1:]
            return
        main(is_batch=True)
    elif argv[1].lower() == 'commit-batch':
      if is_batch and len(gam_batch._order) != 0:
        print 'executing batch'
        gam_batch.execute()
        gam_batch = BatchHttpRequest()
    elif argv[1].lower() == 'version':
      doGAMVersion()
      return 0
    elif argv[1].lower() == 'create':
      if argv[2].lower() == 'user':
        doCreateUser()
      elif argv[2].lower() == 'group':
        doCreateGroup()
      elif argv[2].lower() in ['nickname', 'alias']:
        doCreateAlias()
      elif argv[2].lower() == 'org':
        doCreateOrg()
      elif argv[2].lower() == 'resource':
        doCreateResource()
      else:
        print 'Error: invalid argument to "gam create..."'
        return 2
    elif argv[1].lower() == 'update':
      if argv[2].lower() == 'user':
        doUpdateUser([argv[3],])
      elif argv[2].lower() == 'group':
        doUpdateGroup()
      elif argv[2].lower() in ['ou', 'org']:
        doUpdateOrg()
      elif argv[2].lower() == 'resource':
        doUpdateResourceCalendar()
      elif argv[2].lower() == 'domain':
        doUpdateDomain()
      elif argv[2].lower() == 'cros':
        doUpdateCros()
      elif argv[2].lower() == 'mobile':
        doUpdateMobile()
      else:
        showUsage()
        print 'Error: invalid argument to "gam update..."'
        return 2
    elif argv[1].lower() == 'info':
      if argv[2].lower() == 'user':
        doGetUserInfo()
      elif argv[2].lower() == 'group':
        doGetGroupInfo()
      elif argv[2].lower() in ['nickname', 'alias']:
        doGetAliasInfo()
      elif argv[2].lower() == 'domain':
        doGetDomainInfo()
      elif argv[2].lower() == 'org':
        doGetOrgInfo()
      elif argv[2].lower() == 'resource':
        doGetResourceCalendarInfo()
      elif argv[2].lower() == 'cros':
        doGetCrosInfo()
      elif argv[2].lower() == 'mobile':
        doGetMobileInfo()
      else:
        print 'Error: invalid argument to "gam info..."'
        return 2
    elif argv[1].lower() == 'delete':
      if argv[2].lower() == 'user':
        doDeleteUser()
      elif argv[2].lower() == 'group':
        doDeleteGroup()
      elif argv[2].lower() in ['nickname', 'alias']:
        doDeleteAlias()
      elif argv[2].lower() == 'org':
        doDeleteOrg()
      elif argv[2].lower() == 'resource':
        doDeleteResourceCalendar()
      elif argv[2].lower() == 'mobile':
        doDeleteMobile()
      else:
        print 'Error: invalid argument to "gam delete"'
        return 2
      return 0
    elif argv[1].lower() == 'undelete':
      if argv[2].lower() == 'user':
        doUndeleteUser()
      else:
        print 'Error: invalid argument to "gam undelete..."'
        return 2
      return 0
    elif argv[1].lower() == 'audit':
      if argv[2].lower() == 'monitor':
        if argv[3].lower() == 'create':
          doCreateMonitor()
        elif argv[3].lower() == 'list':
          doShowMonitors()
        elif argv[3].lower() == 'delete':
          doDeleteMonitor()
        else:
          print 'Error: invalid argument to "gam audit monitor..."'
          return 2
      elif argv[2].lower() == 'activity':
        if argv[3].lower() == 'request':
          doRequestActivity()
        elif argv[3].lower() == 'status':
          doStatusActivityRequests()
        elif argv[3].lower() == 'download':
          doDownloadActivityRequest()
        elif argv[3].lower() == 'delete':
          doDeleteActivityRequest()
        else:
          print 'Error: invalid argument to "gam audit activity..."'
          return 2
      elif argv[2].lower() == 'export':
        if argv[3].lower() == 'status':
          doStatusExportRequests()
        elif argv[3].lower() == 'download':
          doDownloadExportRequest()
        elif argv[3].lower() == 'request':
          doRequestExport()
        elif argv[3].lower() == 'delete':
          doDeleteExport()
        else:
          print 'Error: invalid argument to "gam audit export..."'
          return 2
      elif argv[2].lower() == 'uploadkey':
        doUploadAuditKey()
      elif argv[2].lower() == 'admin':
        doAdminAudit()
      else:
        print 'Error: invalid argument to "gam audit..."'
        return 2
    elif argv[1].lower() == 'print':
      if argv[2].lower() == 'users':
        doPrintUsers()
      elif argv[2].lower() == 'nicknames' or argv[2].lower() == 'aliases':
        doPrintAliases()
      elif argv[2].lower() == 'groups':
        doPrintGroups()
      elif argv[2].lower() in ['group-members', 'groups-members']:
        doPrintGroupMembers()
      elif argv[2].lower() in ['orgs', 'ous']:
        doPrintOrgs()
      elif argv[2].lower() == 'resources':
        doPrintResources()
      elif argv[2].lower() == 'cros':
        doPrintCrosDevices()
      elif argv[2].lower() == 'mobile':
        doPrintMobileDevices()
      elif argv[2].lower() in ['license',  'licenses']:
        doPrintLicenses()
      else:
        print 'Error: invalid argument to "gam print..."'
        return 2
      return 0
    elif argv[1].lower() in ['oauth', 'oauth2']:
      if argv[2].lower() in ['request', 'create']:
        doRequestOAuth()
      elif argv[2].lower() == 'info':
        OAuthInfo()
      elif argv[2].lower() in ['delete', 'revoke']:
        doDeleteOAuth()
      elif argv[2].lower() == 'select':
        doOAuthSelect()
      else:
        print 'Error: invalid argument to "gam oauth..."'
        return 2
      return 0
    elif argv[1].lower() == 'calendar':
      if argv[3].lower() == 'showacl':
        doCalendarShowACL()
      elif argv[3].lower() == 'add':
        doCalendarAddACL()
      elif argv[3].lower() in ['del', 'delete']:
        doCalendarDelACL()
      elif argv[3].lower() == 'update':
        doCalendarUpdateACL()
      elif argv[3].lower() == 'wipe':
        doCalendarWipeData()
      else:
        print 'Error: invalid argument to "gam calendar..."'
        return 2
      return 0
    elif argv[1].lower() == 'report':
      showReport()
      return 0
    elif argv[1].lower() == 'whatis':
      doWhatIs()
      return 0
    else:
      users = getUsersToModify()
      command = argv[3].lower()
      if command == 'print':
        for user in users:
          print user
      elif command == 'transfer':
        transferWhat = argv[4].lower()
        if transferWhat == 'drive':
          transferDriveFiles(users)
        elif transferWhat == 'seccals':
          transferSecCals(users)
      elif command == 'show':
        readWhat = argv[4].lower()
        if readWhat in ['labels', 'label']:
          showLabels(users)
        elif readWhat == 'profile':
          showProfile(users)
        elif readWhat == 'calendars':
          showCalendars(users)
        elif readWhat == 'calsettings':
          showCalSettings(users)
        elif readWhat == 'drivesettings':
          showDriveSettings(users)
        elif readWhat == 'filelist':
          showDriveFiles(users)
        elif readWhat == 'fileinfo':
          showDriveFileInfo(users)
        elif readWhat == 'sendas':
          showSendAs(users)
        elif readWhat in ['sig', 'signature']:
          getSignature(users)
        elif readWhat == 'forward':
          getForward(users)
        elif readWhat in ['pop', 'pop3']:
          getPop(users)
        elif readWhat in ['imap', 'imap4']:
          getImap(users)
        elif readWhat == 'vacation':
          getVacation(users)
        elif readWhat in ['delegate', 'delegates']:
          getDelegates(users)
        else:
          print 'Error: invalid argument to "gam <users> show..."'
          return 2
      elif command == 'delete' or command == 'del':
        delWhat = argv[4].lower()
        if delWhat == 'delegate':
          deleteDelegate(users)
        elif delWhat == 'calendar':
          deleteCalendar(users)
        elif delWhat == 'label':
          doDeleteLabel(users)
        elif delWhat == 'photo':
          deletePhoto(users)
        elif delWhat == 'license':
          doLicense(users, 'delete')
        else:
          print 'Error: invalid argument to "gam <users> delete..."'
          return 2
      elif command == 'add':
        addWhat = argv[4].lower()
        if addWhat == 'calendar':
          addCalendar(users)
        elif addWhat == 'drivefile':
          createDriveFile(users)
        elif addWhat == 'license':
          doLicense(users, 'insert')
        else:
          print 'Error: invalid argument to "gam <users> add..."'
          return 2
      elif command == 'update':
        if argv[4].lower() == 'calendar':
          updateCalendar(users)
        elif argv[4].lower() == 'calattendees':
          changeCalendarAttendees(users)
        elif argv[4].lower() == 'photo':
          doPhoto(users)
        elif argv[4].lower() == 'license':
          doLicense(users, 'patch')
        elif argv[4].lower() == 'user':
          doUpdateUser(users)
        else:
          print 'Error: invalid argument to "gam <users> update..."'
          return 2
      elif command == 'get':
        if argv[4].lower() == 'photo':
          getPhoto(users)
      elif command == 'profile':
        doProfile(users)
      elif command == 'imap':
        doImap(users)
      elif command in ['pop', 'pop3']:
        doPop(users)
      elif command == 'sendas':
        doSendAs(users)
      elif command == 'language':
        doLanguage(users)
      elif command in ['utf', 'utf8', 'utf-8', 'unicode']:
        doUTF(users)
      elif command == 'pagesize':
        doPageSize(users)
      elif command == 'shortcuts':
        doShortCuts(users)
      elif command == 'arrows':
        doArrows(users)
      elif command == 'snippets':
        doSnippets(users)
      elif command == 'label':
        doLabel(users)
      elif command == 'filter':
        doFilter(users)
      elif command == 'forward':
        doForward(users)
      elif command in ['sig', 'signature']:
        doSignature(users)
      elif command == 'vacation':
        doVacation(users)
      elif command == 'webclips':
        doWebClips(users)
      elif command in ['delegate', 'delegates']:
        doDelegates(users)
      else:
        print 'Error: %s is not a valid gam command' % command
        return 2
  except IndexError:
    showUsage()
    return 2
  except KeyboardInterrupt:
    sys.exit(1)
  except socket.error, e:
    print '\nError: %s' % e
    return 3
  except MemoryError:
    print 'Error: GAM has run out of memory. If this is a large Google Apps instance, you should use a 64-bit version of GAM on Windows or a 64-bit version of Python on other systems.'
    return 99
  try:
    if not is_batch and len(gam_batch._order) != 0:
      print 'executing batch'
      gam_batch.execute()
  except NameError:
    pass

doGAMCheckForUpdates()
if os.name == 'nt':
  sys.argv = win32_unicode_argv(sys.argv) # cleanup argv on Windows
global argv
if __name__ == '__main__':
  argv = sys.argv
  main()
