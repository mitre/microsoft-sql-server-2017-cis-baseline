# encoding: UTF-8

control "microsoft-sql-server-2017-cis-2.3" do
  title "Ensure 'Cross DB Ownership Chaining' Server Configuration Option is 
set to '0' (Automated)"
  desc "The cross db ownership chaining option controls cross-database ownership
chaining 
across all databases at the instance (or server) level."
  desc "rationale", "When enabled, this option allows a member of the db_owner role in a database to
gain 
access to objects owned by a login in any other database, causing an unnecessary

information disclosure. When required, cross-database ownership chaining should
only be 
enabled for the specific databases requiring it instead of at the instance level
for all 
databases by using the ALTER DATABASE<database_name>SET DB_CHAINING ON command. 

This database option may not be changed on the master, model, or tempdb system 
databases."
  desc "check", "Run the following T-SQL command: 
SELECT name, 
      CAST(value as int) as value_configured, 
      CAST(value_in_use as int) as value_in_use 
FROM sys.configurations 
WHERE name = 'cross db ownership chaining'; 
Both value columns must show 0 to be compliant."
  desc "fix", "Run the following T-SQL command: 
EXECUTE sp_configure 'cross db ownership chaining', 0; 
RECONFIGURE; 
GO"
  desc "default_value", "By default, this option is disabled (0)."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/cross-db-ownership-chaining-server-configuration-option'
  tag nist: ['AC-3 (3)']
  tag severity: "medium"
  tag cis_controls: [
    { '6' => ['14.4'] },
    { '7' => ['14.6'] }
  ] 

  sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'))

  get_all_dbs_query = %{
  SELECT name FROM master.sys.databases;
  GO
  }

  databases = sql_session.query(get_all_dbs_query).column('name')

  databases.each do |db|

    sql_session = mssql_session(
      user: input('user'),
      password: input('password'),
      host: input('host'),
      instance: input('instance'),
      port: input('port'),
      db_name: db)

    cross_db_ownership_query = %{
      SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use
      FROM sys.configurations
      WHERE name = 'cross db ownership chaining';
      GO
    }

    if input('excluded_dbs').include? db
      describe "#{db} db: Database excluded from testing." do
        skip "The #{db} database was excluded from testing by choice of the user."
      end
    else
      describe "#{db} db: Cross DB Ownership Chaining option should be disabled." do
        subject { sql_session.query(cross_db_ownership_query).rows[0] }
        its('value_configured') { should cmp 0 }
        its('value_in_use') { should cmp 0 }
      end
    end
  end
end