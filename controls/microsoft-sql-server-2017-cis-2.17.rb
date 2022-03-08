# encoding: UTF-8

control "microsoft-sql-server-2017-cis-2.17" do
  title "Ensure no login exists with the name 'sa' (Automated)"
  desc "The sa login (e.g. principal) is a widely known and often widely used SQL Server
account. 
Therefore, there should not be a login called sa even when the original sa login

(principal_id = 1) has been renamed."
  desc "rationale", "Enforcing this control reduces the probability of an attacker executing brute
force attacks 
against a well-known principal name."
  desc "check", "Use the following syntax to determine if there is an account named sa. 
SELECT principal_id, name 
FROM sys.server_principals 
WHERE name = 'sa'; 
No rows should be returned."
  desc "fix", "Execute the appropriate ALTER or DROP statement below based on the principal_id 

returned for the login named sa. Replace the <different_name> value within the
below 
syntax and execute to rename the sa login. 
USE [master] 
GO 
  
 
-- If principal_id = 1 or the login owns database objects, rename the sa 
login  
ALTER LOGIN [sa] WITH NAME = <different_name>; 
GO 
-- If the login owns no database objects, then drop it   
-- Do NOT drop the login if it is principal_id = 1 
DROP LOGIN sa"
  desc "impact", "It is not a good security practice to code applications or scripts to use the sa
account. Given 
that it is a best practice to rename and disable the sa account, some 3rd party
applications 
check for the existence of a login named sa and if it doesn't exist, creates
one. Removing the 
sa login will prevent these scripts and applications from authenticating to the
database 
server and executing required tasks or functions."
  desc "default_value", "The login with principal_id = 1 is named sa by default."
  impact 0.5
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
5.1 Minimize And Sparingly Use Administrative Privileges 
 
Minimize administrative privileges and only use administrative accounts when 
they are required. Implement focused auditing on the use of administrative
privileged 
functions and monitor for anomalous behavior."

  sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'))

  sa_login_query = %{
    SELECT principal_id, name
    FROM sys.server_principals
    WHERE name = 'sa';
    }

  describe 'Existing "sa" login' do
    subject { sql_session.query(sa_login_query).rows[0] }
    its('name') { should cmp nil }
  end
end