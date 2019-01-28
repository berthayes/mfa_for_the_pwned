# mfa_for_the_pwned

This script pulls a list of user_ids and email addresses from Duo using the Admin API, then checks those email addresses against the haveibeenpwned.com database.  If the email address has been pwned, then move that user to a group in Duo that is restricted to using ONLY the Duo Mobile App and push for MFA.

For an overview of the Duo Admin API: https://duo.com/docs/adminapi

PLEASE read the a haveibeenpwned.com API documentation: https://haveibeenpwned.com/API/v2 <br>
Specifically this: https://haveibeenpwned.com/API/v2#Abuse <br>
If you don't play by the rules, you'll be blocked.

YOU MUST SPECIFY A UNIQUE USER-AGENT STRING IN YOUR CONFIG
THIS SCRIPT WILL NOT RUN UNLESS YOU EDIT THE .CFG FILE

Sorry for yelling.  The fine folks at haveibeenpwned.com ask that you use a unique user-agent string during your API access.  Please be cool and follow the rule.

When creating permissions in the Duo Admin panel for this instance of API access, include the following:
  <ul>
  <li>Grant Read Information
  <li>Grant Settings
  <li>Grant Read Resource
  <li>Grant Write Resource
  

<pre>
usage: mfa_for_pwned.py [-h] [-f CONF_FILE] [-m METHOD]
                        [--duo_api_params [PARAMS [PARAMS ...]]]
                        [--create_group] [-pwn] [-ua USERAGENT]
                        [--add_to_group]

This script pulls down a list of email addresses from the Duo Admin API. It
then checks those email addresses and usernames against the haveibeenpwnd.com
API. If the account has been pwned, it is moved to a strict MFA group in Duo

optional arguments:
  -h, --help            show this help message and exit
  -f CONF_FILE          config file
  --duo_api_params [PARAMS [PARAMS ...]]
                        parameters to pass to the API
  --create_group        Create a group in Duo
  -pwn                  if true, check for haveibeenpwned.com
  -ua USERAGENT         set the user-agent string for haveibeenpwned.com
  --add_to_group        add popt users to strict MFA group
  </pre>
