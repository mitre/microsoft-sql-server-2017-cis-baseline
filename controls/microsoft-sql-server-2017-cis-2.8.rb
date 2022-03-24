# encoding: UTF-8

control "microsoft-sql-server-2017-cis-2.8" do
  title "Ensure 'Scan For Startup Procs' Server Configuration Option is set to 
'0' (Automated)"
  desc "The scan for startup procs option, if enabled, causes SQL Server to scan for and

automatically run all stored procedures that are set to execute upon service
startup."
  desc "rationale", "Enforcing this control reduces the threat of an entity leveraging these
facilities for 
malicious purposes."
  desc "check", "Run the following T-SQL command: 
SELECT name, 
      CAST(value as int) as value_configured, 
      CAST(value_in_use as int) as value_in_use 
FROM sys.configurations 
WHERE name = 'scan for startup procs'; 
Both value columns must show 0."
  desc "fix", "Run the following T-SQL command: 
EXECUTE sp_configure 'show advanced options', 1; 
RECONFIGURE; 
EXECUTE sp_configure 'scan for startup procs', 0; 
RECONFIGURE; 
  
 
GO 
EXECUTE sp_configure 'show advanced options', 0; 
RECONFIGURE; 
Restart the Database Engine."
  desc "impact", "Setting Scan for Startup Procedures to 0 will prevent certain audit traces and
other 
commonly used monitoring stored procedures from re-starting on start up.
Additionally, 
replication requires this setting to be enabled (1) and will automatically
change this setting 
if needed."
  desc "default_value", "By default, this option is disabled (0)."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/configure-the-scan-for-startup-procs-server-configuration-option'
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
 
Application Software Security"

  sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'))

  startup_procs_query = %{
    SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use
    FROM sys.configurations
    WHERE name = 'scan for startup procs';
  }

  describe "Scan for startup procs option should be disabled." do
    subject { sql_session.query(startup_procs_query).rows[0] }
    its('value_configured') { should cmp 0 }
    its('value_in_use') { should cmp 0 }
  end
end