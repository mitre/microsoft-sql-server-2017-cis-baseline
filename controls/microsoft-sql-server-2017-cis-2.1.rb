# encoding: UTF-8

control "microsoft-sql-server-2017-cis-2.1" do
  title "Ensure 'Ad Hoc Distributed Queries' Server Configuration Option is set to '0'"
  desc "Enabling Ad Hoc Distributed Queries allows users to query data and execute statements on external data sources. This functionality should be disabled."
  desc "rationale", "This feature can be used to remotely access and exploit vulnerabilities on remote SQL Server instances and to run unsafe Visual Basic for Application functions."
  desc "check", "Run the following T-SQL command:
  SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use
  FROM sys.configurations
  WHERE name = 'Ad Hoc Distributed Queries';
  Both value columns must show 0."
  desc "fix", "Run the following T-SQL command:
  EXECUTE sp_configure 'show advanced options', 1; RECONFIGURE;
  EXECUTE sp_configure 'Ad Hoc Distributed Queries', 0; RECONFIGURE;
  GO
  EXECUTE sp_configure 'show advanced options', 0; RECONFIGURE;"
  desc "default_value", "0 (disabled)"
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/ad-hoc-distributed-queries-server-configuration-option'
  tag nist: ['CM-7 (1)']
  tag severity: "medium"
  tag cis_controls: [
    { '6' => ['9.1'] },
    { '7' => ['9.2'] }
  ]
  
  sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'))

  ad_hoc_distributed_query = %{
    SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use
    FROM sys.configurations
    WHERE name = 'Ad Hoc Distributed Queries';
    GO
    }

  describe 'Ad Hoc Distributed Queries should be disabled.' do
    subject { sql_session.query(ad_hoc_distributed_query).rows[0] }
    its('value_configured') { should cmp 0 }
    its('value_in_use') { should cmp 0 }
  end
end