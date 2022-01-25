# encoding: UTF-8

control "microsoft-sql-server-2017-cis-2.9" do
  title "Ensure 'Trustworthy' Database Property is set to 'Off' (Automated)"
  desc "The TRUSTWORTHY database option allows database objects to access objects in
other 
databases under certain circumstances."
  desc "rationale", "Provides protection from malicious CLR assemblies or extended procedures."
  desc "check", "Run the following T-SQL query to list any databases with a Trustworthy database
property 
value of ON: 
SELECT name 
FROM sys.databases 
WHERE is_trustworthy_on = 1 
AND name != 'msdb'; 
No rows should be returned."
  desc "fix", "Execute the following T-SQL statement against the databases (replace
<database_name> 
below) returned by the Audit Procedure: 
ALTER DATABASE [<database_name>] SET TRUSTWORTHY OFF;"
  desc "default_value", "By default, this database property is OFF (is_trustworthy_on = 0), except for
the msdb 
database in which it is required to be ON."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/relational-databases/security/trustworthy-database-property'
  ref 'https://support.microsoft.com/it-it/help/2183687/guidelines-for-using-the-trustworthy-database-setting-in-sql-server'
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
responsibilities. 
 
 
 
"
end