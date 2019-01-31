#! /usr/bin/python

import base64
import email
import hmac
import hashlib
import urllib
from configparser import ConfigParser
import argparse
import requests
import json
import time
import sys

def read_config(conf_file):
	# read config - get money
	cfg = ConfigParser()
	cfg.read(conf_file)
	conf_values = {}
	conf_values['ikey'] = cfg.get('duo_service', 'ikey')
	conf_values['skey'] = cfg.get('duo_service', 'skey')
	conf_values['host'] = cfg.get('duo_service', 'api_host')
	conf_values['group_name'] = cfg.get('duo_service', 'group_name')
	# Also specify a user agent string in the conf file for pwnage checking
	conf_values['useragent'] = cfg.get('haveibeenpwned', 'useragent')
	
	return conf_values

def sign(method, host, path, params, skey, ikey):
    """
    From: https://duo.com/docs/adminapi#overview
    Return HTTP Basic Authentication ("Authorization" and "Date") headers.
    method, host, path: strings from request
    params: dict of request parameters
    skey: secret key
    ikey: integration key
    """
    # create canonical string
    now = email.Utils.formatdate()
    canon = [now, method.upper(), host.lower(), path]
    args = []
    for key in sorted(params.keys()):
        val = params[key]
        unival = unicode(val, "utf-8")
        if isinstance(unival, unicode):
            unival = unival.encode("utf-8")
        args.append(
            '%s=%s' % (urllib.quote(key, '~'), urllib.quote(unival, '~')))
    canon.append('&'.join(args))
    canon = '\n'.join(canon)

    # sign canonical string
    sig = hmac.new(str(skey), str(canon), hashlib.sha1)
    auth = '%s:%s' % (ikey, sig.hexdigest())

    # return headers
    auth_header = {'Date': now, 'Authorization': 'Basic %s' % base64.b64encode(auth)}
    return auth_header

def parse_args():
	# Parse command line args
	args = ()
	parser = argparse.ArgumentParser(description=
	        '''This script pulls down a list of email addresses from the Duo Admin API.
	          It then checks those email addresses and usernames against the haveibeenpwnd.com API.  
	        If the account has been pwned, it is moved to a strict MFA group in Duo

	        Example:                                                                               

	        ./mfa_for_pwned.py --duo_api_params username=bhayes -pwn --add_to_group''')
	parser.add_argument('-f', dest='conf_file', action='store', help='config file')
	parser.add_argument('-v', dest='verbose', action='store_true', help='add verbose output')
	parser.add_argument('--duo_api_params', dest='params', action='store', help='parameters to pass to the API', nargs='*', type=str)
	parser.add_argument('--create_group', dest='create_group', action='store_true', help='Create a group in Duo')
	parser.add_argument('-pwn', dest='pwnage', action='store_true', help='if true, check for haveibeenpwned.com')
	parser.add_argument('-ua', dest='useragent', action='store', help='set the user-agent string for haveibeenpwned.com')
	parser.add_argument('--add_to_group', dest='add_to_group', action='store_true', help='add popt users to strict MFA group')
	parser.add_argument('-d', dest='debug', action='store_true', help='add more output to help debug')
	args = parser.parse_args()
	return args

def do_http(method, host, path, headers, params):
	url = 'https://' + host + path
	if method == 'post':
		try:
			r = requests.post(url, headers=headers, data=params)
			debugprint(method, url, headers, params)
			verboseprint("for url", url, "status_code is", r.status_code)
		except:
			print "could not " + method + " to " + url
		if params['group_id']:
			# dumb hack - if a user is added to a group successfully, there's not content in the response to parse
			# you just get a 200, 400, or 404 status code, so that's what we have to return
			return r.status_code
		rj = r.json()
		resp=rj.get(u'response')
		
	if method == 'get':
		try:
			r = requests.get(url, headers=headers, params=params)
			debugprint(method, headers, params)
			verboseprint("for url", url, "status_code is", r.status_code)
		except:
			print "could not " + method + " to " + url
		rj = r.json()
		resp=rj.get(u'response')

	return resp


def check_pwnage(email_addy,useragent):
	time.sleep(4)
	if 'useragent' in locals():
		headers = {'User-Agent': useragent}
		url = 'https://haveibeenpwned.com/api/v2/breachedaccount/' + email_addy
		debugprint("checking", url)
		debugprint("using user-agent", useragent)
		r = requests.get(url, headers=headers, params='truncateResponse=true')
		debugprint(r.text)
		status_code = (r.status_code)
		verboseprint("status_code for", email_addy, "at haveibeenpwned check is", status_code)
		return status_code
	else:
		error = "You must define YOUR OWN UNIQUE user-agent string in config or CLI"
		print(error)
		sys.exit(1)

def create_duo_group(host, skey, ikey):
	# create a group in Duo that has limited means of MFA
	# https://duo.com/docs/adminapi#create-group
	# Probably better to do this in the GUI Admin Panel
	method = 'post'
	path = '/admin/v1/groups'
	group_params = {}
	group_params['name'] = 'strict_mfa_required'
	group_params['push_enabled'] = 'true'
	group_params['sms_enabled'] = 'false'
	group_params['voice_enabled'] = 'false'
	group_params['mobile_otp_enabled'] = 'false'
	auth_header = sign(method, host, path, group_params, skey, ikey)
	response = do_http(method, host, path, auth_header, group_params)
	#return group_params

def add_to_group(user_id, group_id, host, skey, ikey):
	# Associate this user with the specified group
	# https://duo.com/docs/adminapi#associate-group-with-user
	method = 'post'
	path = '/admin/v1/users/' + user_id + '/groups'
	params = {}
	params['group_id'] = group_id
	auth_header = sign(method, host, path, params, skey, ikey)
	verboseprint("adding user_id", user_id, "to group_id", group_id)
	debugprint(method, host, path, auth_header, params)
	duo_response = do_http(method, host, path, auth_header, params)
	verboseprint("duo_response from add_to_group api call is", duo_response)
	#print(type(duo_response))
	return duo_response

def get_duo_group_id(host, skey, ikey, group_name):
	# Get a list of groups and find the group_id for the one specified
	# https://duo.com/docs/adminapi#retrieve-groups
	method = 'get'
	path = '/admin/v1/groups'
	params = {}
	debugprint(method, host, path, params)
	auth_header = sign(method, host, path, params, skey, ikey)
	debugprint("auth_header is", auth_header)
	duo_response = do_http(method, host, path, auth_header, params)
	debugprint("duo_response is", duo_response)
	for pair in duo_response:
		if pair[u'name'] == group_name:
			group_id = pair['group_id']
			return group_id

def get_duo_user_info(host, skey, ikey, params):
	# Get Duo user info
	# https://duo.com/docs/adminapi#retrieve-users
	method = 'get'
	path = '/admin/v1/users'
	auth_header = sign(method, host, path, params_kv_dict, skey, ikey)
	verboseprint("getting user info from Duo API")
	duo_response = do_http(method, host, path, auth_header, params_kv_dict)
	debugprint("duo_response to get user info is", duo_response)
	list_of_user_info = []
	for pair in duo_response:
		user_info = {}
		debugprint("pair in duo_reponse to get user info is", pair)
		debugprint("parameters fed to Duo API for get user info are:", params_kv_dict)
		email_addy=pair.get(u'email')
		debugprint("email_addy from pair in duo_response user_info is", email_addy)
	 	user_id = pair.get(u'user_id')
	 	debugprint("user_id from pair in duo_response user_info is", user_id)
	 	user_info['email_addy'] = email_addy
	 	user_info['user_id'] = user_id
	 	debugprint("user_info is", user_info)
	 	list_of_user_info.append(user_info)
	debugprint("list_of_user_info is", list_of_user_info, type(list_of_user_info)) 	
	return list_of_user_info
	

#########################
##  Make stuff happen!!
##########################

# Parse command line args first - needed to get config file override
args = parse_args()

if args.verbose:
	def verboseprint(*args):
		# Print each argument separately so caller doesn't need to
		# stuff everything to be printed in a single string
		for arg in args:
			print arg,
		print
else: 
	verboseprint = lambda *a: None # Do nothing function


if args.debug:
	def debugprint(*args):
		for arg in args:
			print arg,
		print
		print
else:
	debugprint = lambda *a: None

if args.conf_file:
	conf_values = read_config(conf_file)
else:
	conf_file = 'duo_api.cfg'

verboseprint("Using", conf_file, "for config file")

conf_values = read_config(conf_file)
host = conf_values['host']
skey = conf_values['skey']
ikey = conf_values['ikey']
# the name of the restricted MFA group in Duo
group_name = conf_values['group_name']
# pull the user-agent string for haveibeenpwned access from the config file too
useragent = conf_values['useragent']
debugprint("useragent from config file is", useragent)


# turn a list of parameters for the Duo API sent as key=value from the CLI into a dictionary
# e.g. blah blah --duo_api_params username=cbroadus
params_kv_dict = {}
if args.params:
	for parameter in args.params:
		key, value = str.split(parameter, '=')
		params_kv_dict[key] = value

if args.create_group:
	duo_response = create_duo_group(host, skey, ikey)

# Retrieve group ID for restricted MFA group - group_name
verboseprint("retrieving group_id for", group_name)
try:
	group_id = str(get_duo_group_id(host, skey, ikey, group_name))
	verboseprint("group_id for ", group_name, "is ", group_id)
except:
	print "could not retrieve group_id for group " + group_name
	sys.exit(1)


# Retrieve a list of hashes of user_ids and email addresses
user_info = get_duo_user_info(host, skey, ikey, params_kv_dict)
debugprint("user_info response is", user_info)

for pair in user_info:
	debugprint("pair is", pair)
	email_addy=pair.get('email_addy')
	user_id = pair.get('user_id')
	if email_addy and args.pwnage:
		verboseprint("checking", email_addy, "at haveibeenpwned")
		status_code = check_pwnage(email_addy,useragent)
		#verboseprint("status code for haveibeenpwned check for", email_addy, status_code)
		if status_code == 200 and args.add_to_group:
			verboseprint(email_addy, "is pwned")
			response = add_to_group(user_id, group_id, host, skey, ikey)
			verboseprint(response)
			if response == 200:
				verboseprint(email_addy, "has been moved to", group_name)
			elif response == 400:
				verboseprint("Invalid or missing parameters when adding user to group - is this user already in the group?")
			elif response == 404:
				verboseprint("user_id with email", email_addy, "is not found")

