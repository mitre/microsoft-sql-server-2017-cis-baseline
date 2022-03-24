# encoding: UTF-8

control "microsoft-sql-server-2017-cis-3.2" do
  title "Ensure CONNECT permissions on the 'guest' user is Revoked within all SQL Server databases excluding the master, msdb and tempdb (Automated)"
  desc "Remove the right of the guest user to connect to SQL Server databases, except
for master, 
msdb, and tempdb."
  desc "rationale", "A login assumes the identity of the guest user when a login has access to SQL
Server but 
does not have access to a database through its own account and the database has
a guest 
user account. Revoking the CONNECT permission for the guest user will ensure
that a login is 
not able to access database information without explicit access to do so."
  desc "check", "Run the following code snippet for each database (replacing <database_name> as 
appropriate) in the instance to determine if the guest user has CONNECT
permission. No 
rows should be returned. 
USE <database_name>; 
GO 
SELECT DB_NAME() AS DatabaseName, 'guest' AS Database_User, 
[permission_name], [state_desc] 
FROM sys.database_permissions  
WHERE [grantee_principal_id] = DATABASE_PRINCIPAL_ID('guest')  
AND [state_desc] LIKE 'GRANT%'  
AND [permission_name] = 'CONNECT' 
AND DB_NAME() NOT IN ('master','tempdb','msdb');"
  desc "fix", "The following code snippet revokes CONNECT permissions from the guest user in a 

database. Replace <database_name> as appropriate: 
USE <database_name>; 
GO 
REVOKE CONNECT FROM guest;"
  desc "additional_information", "The guest user cannot have the CONNECT permission revoked in master, msdb and
tempdb, 
but this permission should be revoked in all other databases on the SQL Server
instance."
  desc "impact", "When CONNECT permission to the guest user is revoked, a SQL Server instance
login must 
be mapped to a database user explicitly in order to have access to the database."
  desc "default_value", "The guest user account is added to each new database but without CONNECT
permission by 
default."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/relational-databases/policy-based-management/guest-permissions-on-user-databases'
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
16 Account Monitoring and Control 
 
Account Monitoring and Control"

  sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'))

  get_all_dbs_query = %{
  SELECT name FROM master.sys.databases;
  GO
  }

  databases = sql_session.query(get_all_dbs_query).column('name')

  databases.each do |db|

    sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'),
    db_name: db)

    guest_connect_query = %{
      SELECT DB_NAME() AS DatabaseName, 'guest' AS Database_User, [permission_name], [state_desc]
      FROM sys.database_permissions
      WHERE [grantee_principal_id] = DATABASE_PRINCIPAL_ID('guest') AND [state_desc] LIKE 'GRANT%'
      AND [permission_name] = 'CONNECT'
      AND DB_NAME() NOT IN ('master','tempdb','msdb');
    }

    noncompliant_guest = sql_session.query(guest_connect_query).column('database_user')

    if input('excluded_dbs').include? db
      describe "#{db} db: Database excluded from testing." do
        skip "The #{db} database was excluded from testing by choice of the user."
      end
    elsif ['master','tempdb','msdb'].include? db
      describe "#{db} db: Not applicable." do
        skip "This control is not applicable to the #{db} database."
      end
    else
      describe "#{db} db: Connect permissions on 'guest'" do
        it "should be revoked." do
          failure_message = "The right of '#{noncompliant_guest.join(", ")}' user(s) to connect to SQL Server databases needs to be removed."
          expect(noncompliant_guest).to be_empty, failure_message
        end
      end
    end
  end
end