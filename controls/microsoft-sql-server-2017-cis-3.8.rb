# encoding: UTF-8

control "microsoft-sql-server-2017-cis-3.8" do
  title "Ensure only the default permissions specified by Microsoft are 
granted to the public server role (Automated)"
  desc "public is a special fixed server role containing all logins. Unlike other fixed
server roles, 
permissions can be changed for the public role. In keeping with the principle of
least 
privileges, the public server role should not be used to grant permissions at
the server 
scope as these would be inherited by all users."
  desc "rationale", "Every SQL Server login belongs to the public role and cannot be removed from
this role. 
Therefore, any permissions granted to this role will be available to all logins
unless they 
have been explicitly denied to specific logins or user-defined server roles."
  desc "check", "Use the following syntax to determine if extra permissions have been granted to
the public 
server role. 
SELECT *  
FROM master.sys.server_permissions 
WHERE (grantee_principal_id = SUSER_SID(N'public') and state_desc LIKE 
'GRANT%') 
AND NOT (state_desc = 'GRANT' and [permission_name] = 'VIEW ANY DATABASE' and 
class_desc = 'SERVER') 
AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and 
class_desc = 'ENDPOINT' and major_id = 2) 
AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and 
class_desc = 'ENDPOINT' and major_id = 3) 
AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and 
class_desc = 'ENDPOINT' and major_id = 4) 
  
 
AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and 
class_desc = 'ENDPOINT' and major_id = 5); 
This query should not return any rows."
  desc "fix", "1. Add the extraneous permissions found in the Audit query results to the
specific 
logins to user-defined server roles which require the access. 
2. Revoke the <permission_name> from the public role as shown below 
USE [master] 
GO 
REVOKE <permission_name> FROM public; 
GO"
  desc "impact", "When the extraneous permissions are revoked from the public server role, access
may be 
lost unless the permissions are granted to the explicit logins or to
user-defined server roles 
containing the logins which require the access."
  desc "default_value", "By default, the public server role is granted VIEW ANY DATABASE permission and
the 
CONNECT permission on the default endpoints (TSQL Local Machine, TSQL Named
Pipes, 
TSQL Default TCP, TSQL Default VIA). The VIEW ANY DATABASE permission allows all

logins to see database metadata, unless explicitly denied."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/relational-databases/security/authentication-access/server-level-roles'
  ref 'https://docs.microsoft.com/en-us/sql/relational-databases/security/authentication-access/server-level-roles#permissions-of-fixed-server-roles'
  tag nist: []
  tag severity: "medium"
  tag cis_controls: " 
Controls 
Version 
Control 
IG 1 IG 2 IG 3 
v7 
14.6 Protect Information through Access Control Lists 
 
Protect all information stored on systems with file system network share claims 

application or database specific access control lists. These controls will
enforce the 
principle that only authorized individuals should have access to the information
based 
on their need to access the information as a part of their responsibilities. 
 
 
 
v6 
5.1 Minimize And Sparingly Use Administrative Privileges 
 
Minimize administrative privileges and only use administrative accounts when
they 
are required. Implement focused auditing on the use of administrative privileged

functions and monitor for anomalous behavior. 
 
 
 
"
end