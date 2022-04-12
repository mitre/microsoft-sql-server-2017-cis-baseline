# encoding: UTF-8

control "microsoft-sql-server-2017-cis-6.2" do
  title "Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS' for All 
CLR Assemblies (Automated)"
  desc "Setting CLR Assembly Permission Sets to SAFE_ACCESS will prevent assemblies from

accessing external system resources such as files, the network, environment
variables, or 
the registry."
  desc "rationale", "Assemblies with EXTERNAL_ACCESS or UNSAFE permission sets can be used to access 

sensitive areas of the operating system, steal and/or transmit data and alter
the state and 
other protection measures of the underlying Windows Operating System. 
Assemblies which are Microsoft-created (is_user_defined = 0) are excluded from
this 
check as they are required for overall system functionality."
  desc "check", "Execute the following SQL statement: 
USE <database_name>; 
GO 
SELECT name, 
      permission_set_desc 
FROM sys.assemblies 
WHERE is_user_defined = 1; 
All the returned assemblies should show SAFE_ACCESS in the permission_set_desc 
column."
  desc "fix", "USE <database_name>; 
GO 
ALTER ASSEMBLY <assembly_name> WITH PERMISSION_SET = SAFE;"
  desc "impact", "The remediation measure should first be tested within a test environment prior
to 
production to ensure the assembly still functions as designed with SAFE
permission setting."
  desc "default_value", "SAFE permission is set by default."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/relational-databases/clr-integration/security/clr-integration-code-access-security'
  ref 'https://docs.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-assemblies-transact-sql'
  ref 'https://docs.microsoft.com/en-us/sql/t-sql/statements/alter-assembly-transact-sql'
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

      clr_assembly_permissions_query = %{
        SELECT name, permission_set_desc
        FROM sys.assemblies
        WHERE is_user_defined = 1
        AND permission_set_desc != 'SAFE_ACCESS';
      }

      noncompliant_clr_assemblies = sql_session.query(clr_assembly_permissions_query).column('name')

      describe "#{db} db: 'CLR Assembly Permission Set'" do
        it "should be set to 'SAFE_ACCESS'." do
          failure_message = "List of user-defined assmeblies without 'SAFE_ACCESS': #{noncompliant_clr_assemblies.join(", ")}"
          expect(noncompliant_clr_assemblies).to be_empty, failure_message
        end
      end
    end
  end
end