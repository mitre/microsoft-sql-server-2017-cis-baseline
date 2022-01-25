# encoding: UTF-8

control "microsoft-sql-server-2017-cis-2.14" do
  title " Ensure the 'sa' Login Account has been renamed (Automated)"
  desc "The sa account is a widely known and often widely used SQL Server login with
sysadmin 
privileges. The sa login is the original login created during installation and
always has 
principal_id=1 and sid=0x01."
  desc "rationale", "It is more difficult to launch password-guessing and brute-force attacks against
the sa login 
if the name is not known."
  desc "check", "Use the following syntax to determine if the sa login (principal) is renamed. 
SELECT name 
FROM sys.server_principals 
WHERE sid = 0x01; 
A name of sa indicates the account has not been renamed and therefore needs
remediation."
  desc "fix", "Replace the <different_user> value within the below syntax and execute to rename
the sa 
login. 
ALTER LOGIN sa WITH NAME = <different_user>;"
  desc "additional_information", "In the case of AWS RDS the default name for this account is rdsa instead of sa."
  desc "impact", "It is not a good security practice to code applications or scripts to use the sa
login. 
However, if this has been done, renaming the sa login will prevent scripts and
applications 
from authenticating to the database server and executing required tasks or
functions."
  desc "default_value", "By default, the sa login name is 'sa'."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode'
  tag nist: []
  tag severity: "medium"
  tag cis_controls: " 
Controls 
Version 
Control 
IG 1 IG 2 IG 3 
v7 
5.1 Establish Secure Configurations 
 
Maintain documented standard security configuration standards for all 
authorized operating systems and software. 
 
 
 
v6 
5 Controlled Use of Administration Privileges 
 
Controlled Use of Administration Privileges 
 
 
 
"
end