# encoding: UTF-8

control "microsoft-sql-server-2017-cis-3.3" do
  title "Ensure 'Orphaned Users' are Dropped From SQL Server Databases 
(Automated)"
  desc "A database user for which the corresponding SQL Server login is undefined or is
incorrectly 
defined on a server instance cannot log in to the instance and is referred to as
orphaned 
and should be removed."
  desc "rationale", "Orphan users should be removed to avoid potential misuse of those broken users
in any 
way."
  desc "check", "Run the following T-SQL query in each database to identify orphan users. No rows
should 
be returned. 
USE [<database_name>]; 
GO 
EXEC sp_change_users_login @Action='Report';"
  desc "fix", "If the orphaned user cannot or should not be matched to an existing or new login
using the 
Microsoft documented process referenced below, run the following T-SQL query in
the 
appropriate database to remove an orphan user: 
USE [<database_name>]; 
GO 
DROP USER <username>;"
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/sql-server/failover-clusters/troubleshoot-orphaned-users-sql-server'
  tag nist: []
  tag severity: "medium"
  tag cis_controls: " 
 
 
Controls 
Version 
Control 
IG 1 IG 2 IG 3 
v7 
16.8 Disable Any Unassociated Accounts 
 
Disable any account that cannot be associated with a business process or 
business owner. 
 
 
 
v6 
16 Account Monitoring and Control 
 
Account Monitoring and Control 
 
 
 
"
end