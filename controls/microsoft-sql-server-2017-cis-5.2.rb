# encoding: UTF-8

control "microsoft-sql-server-2017-cis-5.2" do
  title "Ensure 'Default Trace Enabled' Server Configuration Option is set to '1' (Automated)"
  desc "The default trace provides audit logging of database activity including account
creations, 
privilege elevation and execution of DBCC commands."
  desc "rationale", "Default trace provides valuable audit information regarding security-related
activities on 
the server."
  desc "check", "Run the following T-SQL command: 
SELECT name, 
      CAST(value as int) as value_configured, 
      CAST(value_in_use as int) as value_in_use 
FROM sys.configurations 
WHERE name = 'default trace enabled'; 
Both value columns must show 1."
  desc "fix", "Run the following T-SQL command: 
EXECUTE sp_configure 'show advanced options', 1; 
RECONFIGURE; 
EXECUTE sp_configure 'default trace enabled', 1; 
RECONFIGURE; 
GO 
EXECUTE sp_configure 'show advanced options', 0; 
RECONFIGURE;"
  desc "default_value", "1 (on)"
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option'
  tag nist: []
  tag severity: "medium"
  tag cis_controls: " 
Controls 
Version 
Control 
IG 1 IG 2 IG 3 
v7 
6.2 Activate audit logging 
 
Ensure that local logging has been enabled on all systems and networking
devices. 
 
 
 
v7 
6.3 Enable Detailed Logging 
 
Enable system logging to include detailed information such as an event source
date 
user timestamp source addresses destination addresses and other useful elements.

 
 
 
v6 
6.2 Ensure Audit Log Settings Support Appropriate Log Entry 
Formatting 
 
Validate audit log settings for each hardware device and the software installed
on it 
ensuring that logs include a date timestamp source addresses destination
addresses 
and various other useful elements of each packet and or transaction. Systems
should 
record logs in a standardized format such as syslog entries or those outlined by
the 
Common Event Expression initiative. If systems cannot generate logs in a
standardized 
format log normalization tools can be deployed to convert logs into such a
format."

  sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'))

  default_trace_query = %{
    SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use
    FROM sys.configurations
    WHERE name = 'default trace enabled';
  }

  describe "Default Trace should be enabled in server configuration." do
    subject { sql_session.query(default_trace_query).rows[0] }
    its('value_configured') { should cmp 1 }
    its('value_in_use') { should cmp 1 }
  end
end