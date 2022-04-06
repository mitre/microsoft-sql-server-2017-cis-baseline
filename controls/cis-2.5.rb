# encoding: UTF-8

control "microsoft-sql-server-2017-cis-2.5" do
  title "Ensure 'Ole Automation Procedures' Server Configuration Option is 
set to '0' (Automated)"
  desc "The Ole Automation Procedures option controls whether OLE Automation objects can
be 
instantiated within Transact-SQL batches. These are extended stored procedures
that allow 
SQL Server users to execute functions external to SQL Server."
  desc "rationale", "Enabling this option will increase the attack surface of SQL Server and allow
users to 
execute functions in the security context of SQL Server."
  desc "check", "Run the following T-SQL command: 
SELECT name,  
      CAST(value as int) as value_configured,  
      CAST(value_in_use as int) as value_in_use  
FROM sys.configurations  
WHERE name = 'Ole Automation Procedures';  
Both value columns must show 0 to be compliant."
  desc "fix", "Run the following T-SQL command: 
EXECUTE sp_configure 'show advanced options', 1; 
RECONFIGURE; 
EXECUTE sp_configure 'Ole Automation Procedures', 0; 
RECONFIGURE; 
GO 
EXECUTE sp_configure 'show advanced options', 0; 
RECONFIGURE;"
  desc "default_value", "By default, this option is disabled (0)."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/ole-automation-procedures-server-configuration-option'
  tag nist: ['SI-1', 'CM-6']
  tag severity: "medium"
  tag cis_controls: [
    { '6' => ['18'] },
    { '7' => ['5.1'] }
  ]
  
  sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'))

  ole_automation_procedures_query = %{
    SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use
    FROM sys.configurations
    WHERE name = 'Ole Automation Procedures';
  }

  describe "Ole Automation Procedures option should be disabled." do
    subject { sql_session.query(ole_automation_procedures_query).rows[0] }
    its('value_configured') { should cmp 0 }
    its('value_in_use') { should cmp 0 }
  end
end