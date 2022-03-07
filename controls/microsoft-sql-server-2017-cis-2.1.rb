# encoding: UTF-8

control "microsoft-sql-server-2017-cis-2.1" do
  title "Ensure 'Ad Hoc Distributed Queries' Server Configuration Option is set to '0'"

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