# encoding: UTF-8

control "microsoft-sql-server-2017-cis-2.13" do
  title "Ensure the 'sa' Login Account is set to 'Disabled' (Automated)"
  desc "The sa account is a widely known and often widely used SQL Server account with
sysadmin 
privileges. This is the original login created during installation and always
has the 
principal_id=1 and sid=0x01."
  desc "rationale", "Enforcing this control reduces the probability of an attacker executing brute
force attacks 
against a well-known principal."
  desc "check", "Use the following syntax to determine if the sa account is disabled. Checking
for sid=0x01 
ensures that the original sa account is being checked in case it has been
renamed per best 
practices. 
SELECT name, is_disabled 
FROM sys.server_principals 
WHERE sid = 0x01 
AND is_disabled = 0; 
No rows should be returned to be compliant. 
An is_disabled value of 0 indicates the login is currently enabled and therefore
needs 
remediation."
  desc "fix", "Execute the following T-SQL query: 
  
 
USE [master] 
GO 
DECLARE @tsql nvarchar(max) 
SET @tsql = 'ALTER LOGIN ' + SUSER_NAME(0x01) + ' DISABLE' 
EXEC (@tsql) 
GO"
  desc "additional_information", "In the case of AWS RDS the default name for this account is rdsa instead of sa."
  desc "impact", "It is not a good security practice to code applications or scripts to use the sa
account. 
However, if this has been done, disabling the sa account will prevent scripts
and 
applications from authenticating to the database server and executing required
tasks or 
functions."
  desc "default_value", "By default, the sa login account is disabled at install time when Windows
Authentication 
Mode is selected. If mixed mode (SQL Server and Windows Authentication) is
selected at 
install, the default for the sa login is enabled."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-server-principals-transact-sql'
  ref 'https://docs.microsoft.com/en-us/sql/t-sql/statements/alter-login-transact-sql'
  ref 'https://docs.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode'
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
business 
owner. 
 
 
 
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
    SELECT name, is_disabled FROM sys.server_principals
    WHERE sid = 0x01 AND is_disabled = 0;
    }

  describe '"sa" login account should be disabled.' do
    subject { sql_session.query(sa_login_query).rows[0] }
    its('name') { should cmp nil }
  end
end