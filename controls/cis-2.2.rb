# encoding: UTF-8

control "microsoft-sql-server-2017-cis-2.2" do
  title "Ensure 'CLR Enabled' Server Configuration Option is set to '0' 
(Automated)"
  desc "The clr enabled option specifies whether user assemblies can be run by SQL
Server."
  desc "rationale", "Enabling use of CLR assemblies widens the attack surface of SQL Server and puts
it at risk 
from both inadvertent and malicious assemblies."
  desc "check", "Run the following T-SQL command: 
SELECT name, 
      CAST(value as int) as value_configured, 
      CAST(value_in_use as int) as value_in_use 
  
 
FROM sys.configurations 
WHERE name = 'clr strict security'; 
If both values are 1, this recommendation is Not Applicable. Otherwise, run the
following T-
SQL command: 
SELECT name, 
      CAST(value as int) as value_configured, 
      CAST(value_in_use as int) as value_in_use 
FROM sys.configurations 
WHERE name = 'clr enabled'; 
Both value columns must show 0 to be compliant."
  desc "fix", "Run the following T-SQL command: 
EXECUTE sp_configure 'clr enabled', 0; 
RECONFIGURE;"
  desc "additional_information", "If clr strict security is set to 1 this recommendation is not applicable. By
default, clr 
strict security is enabled and treats SAFE and EXTERNAL_ACCESS assemblies as if
they 
were marked UNSAFE. Though not recommended, the clr strict security option can
be 
disabled for backward compatibility. This recommendation has been retained for 
environments configured for backwards compatibility."
  desc "impact", "If CLR assemblies are in use, applications may need to be rearchitected to
eliminate their 
usage before disabling this setting. Alternatively, some organizations may allow
this setting 
to be enabled 1 for assemblies created with the SAFE permission set, but
disallow 
assemblies created with the riskier UNSAFE and EXTERNAL_ACCESS permission sets.
To find 
user-created assemblies, run the following query in all databases, replacing 
<database_name> with each database name: 
USE [<database_name>] 
GO 
SELECT name AS Assembly_Name, permission_set_desc 
FROM sys.assemblies 
WHERE is_user_defined = 1; 
GO"
  desc "default_value", "By default, this option is disabled (0)."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/t-sql/statements/create-assembly-transact-sql'
  tag nist: ['CM-6', 'CM-7']
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

      clr_enabled_query = %{
        SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use
        FROM sys.configurations
        WHERE name = 'clr enabled';
      }
      
      if sql_session.query(user_created_assemblies_query).rows[1].nil?
        impact 0.0
        describe "#{db} db: No user-created assemblies found." do
          skip "#{db} db: This control is not applicable as no user-created assemblies were found."
        end
      else
        describe.one do
          describe "#{db} db: CLR Strict Security should be enabled." do
            subject { sql_session.query(clr_strict_security_query).rows[0] }
            its('value_configured') { should cmp 1 }
            its('value_in_use') { should cmp 1 }
          end
          describe "#{db} db: CLR should be enabled." do
            subject { sql_session.query(clr_enabled_query).rows[0] }
            its('value_configured') { should cmp 0 }
            its('value_in_use') { should cmp 0 }
          end
        end
      end
    end
  end
end