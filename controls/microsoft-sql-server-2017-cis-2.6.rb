# encoding: UTF-8

control "microsoft-sql-server-2017-cis-2.6" do
  title "Ensure 'Remote Access' Server Configuration Option is set to '0' 
(Automated)"
  desc "The remote access option controls the execution of local stored procedures on
remote 
servers or remote stored procedures on local server."
  desc "rationale", "Functionality can be abused to launch a Denial-of-Service (DoS) attack on remote
servers 
by off-loading query processing to a target."
  desc "check", "Run the following T-SQL command: 
SELECT name, 
      CAST(value as int) as value_configured, 
      CAST(value_in_use as int) as value_in_use 
FROM sys.configurations 
WHERE name = 'remote access'; 
Both value columns must show 0."
  desc "fix", "Run the following T-SQL command: 
EXECUTE sp_configure 'show advanced options', 1; 
RECONFIGURE; 
EXECUTE sp_configure 'remote access', 0; 
RECONFIGURE; 
GO 
  
 
EXECUTE sp_configure 'show advanced options', 0; 
RECONFIGURE; 
Restart the Database Engine."
  desc "impact", "Per Microsoft: This feature will be removed in the next version of Microsoft SQL
Server. Do 
not use this feature in new development work, and modify applications that
currently use 
this feature as soon as possible. Use sp_addlinkedserver instead."
  desc "default_value", "By default, this option is enabled (1)."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/configure-the-remote-access-server-configuration-option'
  tag nist: []
  tag severity: "medium"
  tag cis_controls: " 
Controls 
Version 
Control 
IG 1 IG 2 IG 3 
v7 
9.2 Ensure Only Approved Ports Protocols and Services 
Are Running 
 
Ensure that only network ports protocols and services listening on a system 
with validated business needs are running on each system. 
 
 
 
v6 
9.1 Limit Open Ports Protocols and Services 
 
Ensure that only ports protocols and services with validated business needs 
are running on each system. 
 
 
 
"
end