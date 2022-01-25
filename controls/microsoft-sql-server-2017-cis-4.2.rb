# encoding: UTF-8

control "microsoft-sql-server-2017-cis-4.2" do
  title "Ensure 'CHECK_EXPIRATION' Option is set to 'ON' for All SQL 
Authenticated Logins Within the Sysadmin Role (Automated)"
  desc "Applies the same password expiration policy used in Windows to passwords used
inside 
SQL Server."
  desc "rationale", "Ensuring SQL logins comply with the secure password policy applied by the
Windows 
Server Benchmark will ensure the passwords for SQL logins with sysadmin
privileges are 
changed on a frequent basis to help prevent compromise via a brute force attack.
CONTROL 
SERVER is an equivalent permission to sysadmin and logins with that permission
should 
also be required to have expiring passwords."
  desc "check", "Run the following T-SQL statement to find sysadmin or equivalent logins with 
CHECK_EXPIRATION = OFF. No rows should be returned. 
SELECT l.[name], 'sysadmin membership' AS 'Access_Method' 
FROM sys.sql_logins AS l 
WHERE IS_SRVROLEMEMBER('sysadmin',name) = 1 
AND l.is_expiration_checked <> 1 
UNION ALL 
SELECT l.[name], 'CONTROL SERVER' AS 'Access_Method' 
FROM sys.sql_logins AS l 
JOIN sys.server_permissions AS p 
ON l.principal_id = p.grantee_principal_id 
WHERE p.type = 'CL' AND p.state IN ('G', 'W') 
AND l.is_expiration_checked <> 1;"
  desc "fix", "For each <login_name> found by the Audit Procedure, execute the following T-SQL 

statement: 
ALTER LOGIN [<login_name>] WITH CHECK_EXPIRATION = ON;"
  desc "impact", "This is a mitigating recommendation for systems which cannot follow the
recommendation 
to use only Windows Authenticated logins. 
Regarding limiting this rule to only logins with sysadmin and CONTROL SERVER
privileges, 
there are too many cases of applications that run with less than sysadmin level
privileges 
that have hard-coded passwords or effectively hard-coded passwords (whatever is
set the 
first time is nearly impossible to change). There are several line-of-business
applications 
that are considered best of breed which have this failing. 
Also, keep in mind that the password policy is taken from the computer's local
policy, 
which is taken from the Default Domain Policy setting. Many organizations have a
different 
password policy regarding the service accounts. These are handled in AD by
setting the 
account's password to not expire and having some other process track when the
password 
needs to be changed. With this second control in place, this is perfectly
acceptable from an 
audit perspective. If you treat a SQL Server login as a service account, then
you have to do 
the same. This ensures that the password change happens during a communicated 
downtime window and not arbitrarily."
  desc "default_value", "CHECK_EXPIRATION is ON by default when using SSMS to create a SQL authenticated
login. 
CHECK_EXPIRATION is OFF by default when using T-SQL CREATE LOGIN syntax without 

specifying the CHECK_EXPIRATION option."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/relational-databases/security/password-policy?view=sql-server-2017'
  tag nist: []
  tag severity: "medium"
  tag cis_controls: " 
Controls 
Version 
Control 
IG 1 IG 2 IG 3 
v7 
16.10 Ensure All Accounts Have An Expiration Date 
 
Ensure that all accounts have an expiration date that is monitored and 
enforced. 
 
 
 
v6 
16.2 All Accounts Have A Monitored Expiration Date 
 
Ensure that all accounts have an expiration date that is monitored and 
enforced. 
 
 
 
"
end