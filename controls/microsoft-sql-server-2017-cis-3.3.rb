# encoding: UTF-8

control "microsoft-sql-server-2017-cis-3.3" do
  title "Ensure 'Orphaned Users' are Dropped From SQL Server Databases 
(Automated)"
  desc "A database user for which the corresponding SQL Server login is undefined or is
incorrectly 
defined on a server instance cannot log in to the instance and is referred to as
orphaned 
and should be removed."
  desc "rationale", "Orphan users should be removed to avoid potential misuse of those broken users
in any 
way."
  desc "check", "Run the following T-SQL query in each database to identify orphan users. No rows
should 
be returned. 
USE [<database_name>]; 
GO 
EXEC sp_change_users_login @Action='Report';"
  desc "fix", "If the orphaned user cannot or should not be matched to an existing or new login
using the 
Microsoft documented process referenced below, run the following T-SQL query in
the 
appropriate database to remove an orphan user: 
USE [<database_name>]; 
GO 
DROP USER <username>;"
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/sql-server/failover-clusters/troubleshoot-orphaned-users-sql-server'
  tag nist: ['AC-2']
  tag severity: "medium"
  tag cis_controls: [
    { '6' => ['16'] },
    { '7' => ['16.8'] }
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

    orphaned_users_query = %{
      EXEC sp_change_users_login @Action='Report';
    }

    orphaned_users = sql_session.query(orphaned_users_query).column('username')

    if input('excluded_dbs').include? db
      describe "#{db} db: Database excluded from testing." do
        skip "The #{db} database was excluded from testing by choice of the user."
      end
    else
      describe "#{db} db: Orphaned users" do
        it "should be removed." do
          failure_message = "These orphaned users need to be removed: #{orphaned_users.join(", ")}"
          expect(orphaned_users).to be_empty, failure_message
        end
      end
    end
  end
end