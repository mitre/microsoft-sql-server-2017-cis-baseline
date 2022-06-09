# encoding: UTF-8

control "microsoft-sql-server-2017-cis-2.15" do
  title "Ensure 'xp_cmdshell' Server Configuration Option is set to '0' 
(Automated)"
  desc "The xp_cmdshell option controls whether the xp_cmdshell extended stored
procedure can 
be used by an authenticated SQL Server user to execute operating-system command
shell 
commands and return results as rows within the SQL client."
  desc "rationale", "The xp_cmdshell procedure is commonly used by attackers to read or write data
to/from 
the underlying Operating System of a database server."
  desc "check", "Run the following T-SQL command: 
SELECT name, 
      CAST(value as int) as value_configured, 
      CAST(value_in_use as int) as value_in_use 
FROM sys.configurations 
WHERE name = 'xp_cmdshell'; 
Both value columns must show 0 to be compliant."
  desc "fix", "Run the following T-SQL command: 
EXECUTE sp_configure 'show advanced options', 1; 
RECONFIGURE; 
EXECUTE sp_configure 'xp_cmdshell', 0; 
RECONFIGURE;  
GO  
EXECUTE sp_configure 'show advanced options', 0; 
RECONFIGURE;"
  desc "default_value", "By default, this option is disabled (0)."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql'
  ref 'https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option'
  tag nist: ['SI-1', 'CM-7 (1)']
  tag severity: "medium"
  tag cis_controls: [
    { '6' => ['18'] },
    { '7' => ['9.2'] }
  ]

  sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'))

  xp_cmdshell_query = %{
    SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use
    FROM sys.configurations
    WHERE name = 'xp_cmdshell';
    }

  describe 'xp_cmdshell option should be disabled.' do
    subject { sql_session.query(xp_cmdshell_query).rows[0] }
    its('value_configured') { should cmp 0 }
    its('value_in_use') { should cmp 0 }
  end
end