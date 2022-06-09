# encoding: UTF-8

control "microsoft-sql-server-2017-cis-2.18" do
  title "Ensure 'clr strict security' Server Configuration Option is set to '1' 
(Automated)"
  desc "The clr strict security option specifies whether the engine applies the
PERMISSION_SET 
on the assemblies."
  desc "rationale", "Enabling use of CLR assemblies widens the attack surface of SQL Server and puts
it at risk 
from both inadvertent and malicious assemblies."
  desc "check", "Run the following T-SQL command: 
SELECT name, 
      CAST(value as int) as value_configured, 
      CAST(value_in_use as int) as value_in_use 
FROM sys.configurations 
WHERE name = 'clr strict security'; 
  
 
Both value columns must show 1 to be compliant."
  desc "fix", "Run the following T-SQL command: 
EXECUTE sp_configure 'show advanced options', 1; 
RECONFIGURE; 
EXECUTE sp_configure 'clr strict security', 1; 
RECONFIGURE; 
GO 
EXECUTE sp_configure 'show advanced options', 0; 
RECONFIGURE;"
  desc "impact", "If CLR assemblies are in use, applications may need to be rearchitected to
eliminate their 
usage before enabling this setting. To find user-created assemblies, run the
following query 
in all databases, replacing <database_name> with each database name: 
USE [<database_name>] 
GO 
SELECT name AS Assembly_Name, permission_set_desc 
FROM sys.assemblies 
WHERE is_user_defined = 1; 
GO"
  desc "default_value", "By default, this option is Enabled (1)."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/clr-strict-security?view=sql-server-2017'
  tag nist: ['CM-7', 'CM-6']
  tag severity: "medium"
  tag cis_controls: [
    { '6' => ['18.9'] },
    { '7' => ['18.11'] }
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

  inaccessible_dbs_query = %{
    SELECT name FROM master.sys.databases
    WHERE HAS_DBACCESS([name]) = 0;
  }
  inaccessible_dbs = sql_session.query(inaccessible_dbs_query).column('name')

  databases.each do |db|
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
      
      user_created_assemblies_query = %{
        SELECT name AS Assembly_Name, permission_set_desc
        FROM sys.assemblies
        WHERE is_user_defined = 1;
        GO
      }

      clr_strict_security_query = %{
        SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use
        FROM sys.configurations
        WHERE name = 'clr strict security';
      }

      if sql_session.query(user_created_assemblies_query).rows[1].nil?
        impact 0.0
        describe "#{db} db: No user-created assemblies found." do
          skip "#{db} db: This control is not applicable as no user-created assemblies were found."
        end
      else
        describe "#{db} db: CLR Strict Security should be enabled." do
          subject { sql_session.query(clr_strict_security_query).rows[0] }
          its('value_configured') { should cmp 1 }
          its('value_in_use') { should cmp 1 }
        end
      end
    end
  end
end