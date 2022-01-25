# encoding: UTF-8

control "microsoft-sql-server-2017-cis-2.16" do
  title " Ensure 'AUTO_CLOSE' is set to 'OFF' on contained databases 
(Automated)"
  desc "AUTO_CLOSE determines if a given database is closed or not after a connection
terminates. If 
enabled, subsequent connections to the given database will require the database
to be 
reopened and relevant procedure caches to be rebuilt."
  desc "rationale", "Because authentication of users for contained databases occurs within the
database not at 
the server\\instance level, the database must be opened every time to
authenticate a user. 
The frequent opening/closing of the database consumes additional server
resources and 
may contribute to a denial of service."
  desc "check", "Perform the following to find contained databases that are not configured as
prescribed: 
SELECT name, containment, containment_desc, is_auto_close_on 
FROM sys.databases 
WHERE containment <> 0 and is_auto_close_on = 1; 
No rows should be returned."
  desc "fix", "Execute the following T-SQL, replacing <database_name> with each database name
found 
by the Audit Procedure: 
ALTER DATABASE <database_name> SET AUTO_CLOSE OFF;"
  desc "default_value", "By default, the database property AUTO_CLOSE is OFF which is equivalent to 
is_auto_close_on = 0."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/relational-databases/databases/security-best-practices-with-contained-databases'
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
18 Application Software Security 
 
Application Software Security 
 
 
 
"
end