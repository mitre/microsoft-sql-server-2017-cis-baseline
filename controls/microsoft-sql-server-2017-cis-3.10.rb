# encoding: UTF-8

control "microsoft-sql-server-2017-cis-3.10" do
  title "Ensure Windows local groups are not SQL Logins (Automated)"
  desc "Local Windows groups should not be used as logins for SQL Server instances."
  desc "rationale", "Allowing local Windows groups as SQL Logins provides a loophole whereby anyone
with 
OS level administrator rights (and no SQL Server rights) could add users to the
local 
Windows groups and thereby give themselves or others access to the SQL Server
instance."
  desc "check", "Use the following syntax to determine if any local groups have been added as SQL
Server 
Logins. 
USE [master] 
GO 
SELECT pr.[name] AS LocalGroupName, pe.[permission_name], pe.[state_desc] 
FROM sys.server_principals pr 
JOIN sys.server_permissions pe 
ON pr.[principal_id] = pe.[grantee_principal_id] 
WHERE pr.[type_desc] = 'WINDOWS_GROUP' 
AND pr.[name] like CAST(SERVERPROPERTY('MachineName') AS nvarchar) + '%'; 
This query should not return any rows."
  desc "fix", "1. For each LocalGroupName login, if needed create an equivalent AD group
containing 
only the required user accounts. 
2. Add the AD group or individual Windows accounts as a SQL Server login and
grant it 
the permissions required. 
3. Drop the LocalGroupName login using the syntax below after replacing <name>. 

  
 
USE [master] 
GO 
DROP LOGIN [<name>] 
GO"
  desc "impact", "Before dropping the local group logins, ensure that alternative AD Groups or
Windows 
logins have been added with equivalent permissions. Otherwise, the SQL Server
instance 
may become totally inaccessible."
  desc "default_value", "By default, no local groups are added as SQL logins."
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

  win_local_query = %{
    SELECT pr.[name], pe.[permission_name], pe.[state_desc] FROM sys.server_principals pr
    JOIN sys.server_permissions pe
    ON pr.[principal_id] = pe.[grantee_principal_id]
    WHERE pr.[type_desc] = 'WINDOWS_GROUP'
    AND pr.[name] like CAST(SERVERPROPERTY('MachineName') AS nvarchar) + '%';
    }

  noncompliant_groups = sql_session.query(win_local_query).column('name')

  describe "Windows local groups" do
    it "should not be SQL logins." do
      failure_message = "These Windows local groups should not be SQL logins: #{noncompliant_groups.join(", ")}"
      expect(noncompliant_groups).to be_empty, failure_message
    end
  end
end