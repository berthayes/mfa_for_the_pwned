# mfa_for_the_pwned

This script pulls a list of user_ids and email addresses from Duo using the Admin API, then checks those email addresses against the haveibeenpwned.com database.  If the email address has been pwned, then move it to a group in Duo that is restricted to using ONLY the Duo Mobile App and push for MFA.

For an overview of the Duo Admin API: https://duo.com/docs/adminapi

PLEASE read the a haveibeenpwned.com API documentation: https://haveibeenpwned.com/API/v2 <br>
Specifically this: https://haveibeenpwned.com/API/v2#Abuse <br>
If you don't play by the rules, you'll be blocked.

YOU MUST SPECIFY A UNIQUE USER-AGENT STRING IN YOUR CONFIG
THIS SCRIPT WILL NOT RUN UNLESS YOU EDIT THE .CFG FILE

Sorry for yelling.  The fine folks at haveibeenpwned.com as that you use a unique user-agent string during your API access.  Please be cool and follow the rule.

When creating permissions in the Duo Admin panel for this instance of API access, include the following:
  <ul>
  <li>Grant Read Information
  <li>Grant Settings
  <li>Grant Read Resource
  <li>Grant Write Resource
  
