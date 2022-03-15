# encoding: UTF-8

control "microsoft-sql-server-2017-cis-3.9" do
  title "Ensure Windows BUILTIN groups are not SQL Logins (Automated)"
  desc "Prior to SQL Server 2008, the BUILTIN\\Administrators group was added as a SQL
Server 
login with sysadmin privileges during installation by default. Best practices
promote 
creating an Active Directory level group containing approved DBA staff accounts
and using 
this controlled AD group as the login with sysadmin privileges. The AD group
should be 
specified during SQL Server installation and the BUILTIN\\Administrators group
would 
therefore have no need to be a login."
  desc "rationale", "The BUILTIN groups (Administrators, Everyone, Authenticated Users, Guests, etc.)
generally 
contain very broad memberships which would not meet the best practice of
ensuring only 
the necessary users have been granted access to a SQL Server instance. These
groups 
should not be used for any level of access into a SQL Server Database Engine
instance."
  desc "check", "Use the following syntax to determine if any BUILTIN groups or accounts have
been added 
as SQL Server Logins. 
SELECT pr.[name], pe.[permission_name], pe.[state_desc] 
FROM sys.server_principals pr 
JOIN sys.server_permissions pe 
ON pr.principal_id = pe.grantee_principal_id 
WHERE pr.name like 'BUILTIN%'; 
This query should not return any rows."
  desc "fix", "1. For each BUILTIN login, if needed create a more restrictive AD group
containing only 
the required user accounts. 
2. Add the AD group or individual Windows accounts as a SQL Server login and
grant it 
the permissions required. 
3. Drop the BUILTIN login using the syntax below after replacing <name> in 
[BUILTIN\\<name>]. 
USE [master] 
GO 
DROP LOGIN [BUILTIN\\<name>] 
GO"
  desc "impact", "Before dropping the BUILTIN group logins, ensure that alternative AD Groups or
Windows 
logins have been added with equivalent permissions. Otherwise, the SQL Server
instance 
may become totally inaccessible."
  desc "default_value", "By default, no BUILTIN groups are added as SQL logins."
  impact 0.5
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
14.4 Protect Information With Access Control Lists 
 
All information stored on systems shall be protected with file system network 
share claims application or database specific access control lists. These
controls will 
enforce the principle that only authorized individuals should have access to the

information based on their need to access the information as a part of their 
responsibilities."

  sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'))

  win_builtin_query = %{
    SELECT pr.[name], pe.[permission_name], pe.[state_desc] FROM sys.server_principals pr
    JOIN sys.server_permissions pe
    ON pr.principal_id = pe.grantee_principal_id
    WHERE pr.name like 'BUILTIN%';
    }

  describe "Windows Built-in groups should not be SQL logins." do
    subject { sql_session.query(win_builtin_query).rows[0] }
    its('name') { should cmp nil }
  end
end