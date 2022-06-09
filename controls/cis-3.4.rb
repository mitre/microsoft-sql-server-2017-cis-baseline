# encoding: UTF-8

control "microsoft-sql-server-2017-cis-3.4" do
  title "Ensure SQL Authentication is not used in contained databases 
(Automated)"
  desc "Contained databases do not enforce password complexity rules for SQL
Authenticated 
users."
  desc "rationale", "The absence of an enforced password policy may increase the likelihood of a weak

credential being established in a contained database."
  desc "check", "Execute the following T-SQL in each contained database to find database users
that are 
using SQL authentication: 
SELECT name AS DBUser 
FROM sys.database_principals 
WHERE name NOT IN ('dbo','Information_Schema','sys','guest') 
AND type IN ('U','S','G') 
AND authentication_type = 2; 
GO"
  desc "fix", "Leverage Windows Authenticated users in contained databases."
  desc "impact", "While contained databases provide flexibility in relocating databases to
different instances 
and different environments, this must be balanced with the consideration that no
password 
policy mechanism exists for SQL Authenticated users in contained databases."
  desc "default_value", "SQL Authenticated users (USER WITH PASSWORD authentication) are allowed in
contained 
databases."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/relational-databases/databases/security-best-practices-with-contained-databases'
  tag nist: ['IA-2', 'AC-2']
  tag severity: "medium"
  tag cis_controls: [
    { '6' => ['16.12'] },
    { '7' => ['16.2'] }
  ]
  
  sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'))

  contained_dbs_query = %{
    SELECT name, containment, containment_desc
    FROM sys.databases
    WHERE containment <> 0
  }

  contained_dbs = sql_session.query(contained_dbs_query).column('name')

  inaccessible_dbs_query = %{
    SELECT name FROM master.sys.databases
    WHERE HAS_DBACCESS([name]) = 0;
  }
  inaccessible_dbs = sql_session.query(inaccessible_dbs_query).column('name')

  if contained_dbs.empty?
    impact 0.0
    describe "No contained databases found." do
      skip "This control is not applicable as no contained databases were found."
    end
  else
    contained_dbs.each do |db|
      if input('excluded_dbs').include? db
        describe "#{db} db: Database excluded from testing." do
          skip "The #{db} database was excluded from testing by choice of the user."
        end
      elsif inaccessible_dbs.include? db
        describe "#{db} db: Database is not accessible to this user." do
          skip "The #{db} database is not accessible to this user."
        end
      else
        sql_session = mssql_session(
        user: input('user'),
        password: input('password'),
        host: input('host'),
        instance: input('instance'),
        port: input('port'),
        db_name: db)

        sql_auth_users_query = %{
          SELECT name AS DBUser
          FROM sys.database_principals
          WHERE name NOT IN ('dbo','Information_Schema','sys','guest')
          AND type IN ('U','S','G')
          AND authentication_type = 2;
        }

        sql_auth_users = sql_session.query(sql_auth_users_query).column('dbuser')

        describe "#{db} db: SQL Authentication" do
          it "should not be used in contained databases." do
            failure_message = "#{db} db: #{sql_auth_users.join(', ')} user(s) should not use SQL Authentication in a contained database."
            expect(sql_auth_users).to be_empty, failure_message
          end
        end
      end
    end
  end
end