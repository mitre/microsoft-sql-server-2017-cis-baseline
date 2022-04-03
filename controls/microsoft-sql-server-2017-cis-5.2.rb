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
  tag nist: ['AU-4', 'AU-12']
  tag severity: "medium"
  tag cis_controls: [
    { '6' => ['6.3'] },
    { '7' => ['6.2'] }
  ] 

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