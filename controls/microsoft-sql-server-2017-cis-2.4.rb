# encoding: UTF-8

control "microsoft-sql-server-2017-cis-2.4" do
  title "Ensure 'Database Mail XPs' Server Configuration Option is set to '0' 
(Automated)"
  desc "The Database Mail XPs option controls the ability to generate and transmit email

messages from SQL Server."
  desc "rationale", "Disabling the Database Mail XPs option reduces the SQL Server surface,
eliminates a DOS 
attack vector and channel to exfiltrate data from the database server to a
remote host."
  desc "check", "Run the following T-SQL command: 
SELECT name, 
      CAST(value as int) as value_configured, 
      CAST(value_in_use as int) as value_in_use 
FROM sys.configurations 
WHERE name = 'Database Mail XPs'; 
Both value columns must show 0 to be compliant."
  desc "fix", "Run the following T-SQL command: 
EXECUTE sp_configure 'show advanced options', 1; 
RECONFIGURE; 
EXECUTE sp_configure 'Database Mail XPs', 0; 
RECONFIGURE; 
GO 
EXECUTE sp_configure 'show advanced options', 0; 
RECONFIGURE;"
  desc "default_value", "By default, this option is disabled (0)."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/relational-databases/database-mail/database-mail'
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
18 Application Software Security 
 
Application Software Security"


  sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'))

  database_mail_xps_query = %{
    SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use
    FROM sys.configurations
    WHERE name = 'Database Mail XPs';
  }

  describe "Database Mail XPs option should be disabled." do
    subject { sql_session.query(database_mail_xps_query).rows[0] }
    its('value_configured') { should cmp 0 }
    its('value_in_use') { should cmp 0 }
  end
end