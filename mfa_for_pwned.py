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
	        If the account has been pwned, it is moved to a strict MFA group in Duo''')
	parser.add_argument('-f', dest='conf_file', action='store', help='config file')
	#parser.add_argument('-m', dest='method', action='store', help='HTTP method - e.g. GET or POST')
	#parser.add_argument('-p', dest='path', action='store', help='path or API endpoint to hit')
	parser.add_argument('--duo_api_params', dest='params', action='store', help='parameters to pass to the API', nargs='*', type=str)
	parser.add_argument('--create_group', dest='create_group', action='store_true', help='Create a group in Duo')
	#parser.add_argument('--group_name', dest='group_name', action='store', help='Name of restricted group in Duo')
	parser.add_argument('-pwn', dest='pwnage', action='store_true', help='if true, check for haveibeenpwned.com')
	parser.add_argument('-ua', dest='useragent', action='store', help='set the user-agent string for haveibeenpwned.com')
	parser.add_argument('--add_to_group', dest='add_to_group', action='store_true', help='add popt users to strict MFA group')
	args = parser.parse_args()
	return args

def read_config(conf_file):
	# Read config file to get options
	# if cfg file is specified on command line, use it
	if 'conf_file' in locals():
		conf_file = conf_file
	else:
	# if not, use default		
		conf_file = 'duo_api.cfg'
	#print(conf_file)
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

def do_http(method, host, path, headers, params):
	url = 'https://' + host + path
	if method == 'post':
		r = requests.post(url, headers=headers, data=params)
		#print(r.status_code)
		rj = r.json()
		resp=rj.get(u'response')
		
	if method == 'get':
		r = requests.get(url, headers=headers, params=params)
		#print(r.status_code)
		rj = r.json()
		resp=rj.get(u'response')

	return r
	#print(resp)
	#if resp:
	#	return resp

def check_pwnage(email,useragent):
	time.sleep(4)
	if 'useragent' in locals():
		headers = {'user-agent': useragent}
		url = 'https://haveibeenpwned.com/api/v2/breachedaccount/' + email
		r = requests.get(url, headers=headers, params='truncateResponse=true')
		status_code = (r.status_code)
		return status_code
	else:
		error = "You must define YOUR OWN UNIQUE user-agent string in config or CLI"
		print(error)
		sys.exit(1)

def create_duo_group(host, skey, ikey):
	# create a group in Duo that has limited means of MFA
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
	method = 'post'
	path = '/admin/v1/users/' + user_id + '/groups'
	params = {}
	params['group_id'] = group_id
	auth_header = sign(method, host, path, params, skey, ikey)
	duo_response = do_http(method, host, path, auth_header, params)
	return duo_response

def get_duo_group_id(host, skey, ikey, group_name):
	method = 'get'
	path = '/admin/v1/groups'
	params = {}
	auth_header = sign(method, host, path, params, skey, ikey)
	duo_response = do_http(method, host, path, auth_header, params)
	rj = duo_response.json()
	resp = rj.get(u'response')
	for pair in resp:
		if pair['name'] == group_name:
			group_id = pair['group_id']
			return group_id


#########################
##  Make stuff happen!!
##########################

# Parse command line args first - needed to get config file override
args = parse_args()
if args.conf_file:
	conf_values = read_config(conf_file)
else:
	conf_values = read_config('duo_api.cfg')
#conf_values = read_config(args.conf_file)
host = conf_values['host']
skey = conf_values['skey']
ikey = conf_values['ikey']
# pull the user-agent string from the config file too
useragent = conf_values['useragent']
group_name = conf_values['group_name']


# turn a list of parameters for the Duo API sent as key=value from the CLI into a dictionary
params_kv_dict = {}
if args.params:
	for parameter in args.params:
		key, value = str.split(parameter, '=')
		params_kv_dict[key] = value

if args.create_group:
	duo_response = create_duo_group(host, skey, ikey)

# Retrieve group ID
group_id = str(get_duo_group_id(host, skey, ikey, group_name))
#print(group_id)

# Get Duo user info
method = 'get'
path = '/admin/v1/users'
auth_header = sign(method, host, path, params_kv_dict, skey, ikey)
duo_response = do_http(method, host, path, auth_header, params_kv_dict)
rj = duo_response.json()
resp = rj.get(u'response')

user_info = {}
for pair in resp:
	email_addy=pair.get(u'email')
	user_id = pair.get(u'user_id')
	if email_addy and args.pwnage:
		user_info['email'] = email_addy
		user_info['user_id'] = user_id
		#check to see if email is in haveibeenpwned.com
		message = "checking"
		print message, email_addy
		status_code = check_pwnage(email_addy,useragent)
		if status_code == 200 and args.add_to_group:
			message = "is pwned"
			print email_addy, message
			response = add_to_group(user_id, group_id, host, skey, ikey)
			if response.status_code == 200:
				print 'user moved'

			#print(response)



	




				







