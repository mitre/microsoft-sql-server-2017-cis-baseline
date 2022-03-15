# encoding: UTF-8

control "microsoft-sql-server-2017-cis-3.1" do
  title "Ensure 'Server Authentication' Property is set to 'Windows Authentication Mode'"

  sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'))

  login_mode_query = %{
    SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') as [login_mode];
    }

  describe 'Windows Authentication Mode should be used for server authentication.' do
    subject { sql_session.query(login_mode_query).rows[0] }
    its('login_mode') { should cmp 1 }
  end
end