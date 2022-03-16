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
  tag nist: []
  tag severity: "medium"
  tag cis_controls: " 
Controls 
Version 
Control 
IG 1 IG 2 IG 3 
v7 
5.1 Establish Secure Configurations 
 
Maintain documented standard security configuration standards for all 
authorized operating systems and software. 
 
 
 
v6 
18 Application Software Security 
 
Application Software Security"

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

  databases.each do |db| # map - when passes outnumber failures
    unless input('excluded_dbs').include? db

      clr_assembly_permissions_query = %{
        USE #{db};
        GO
        SELECT name, permission_set_desc
        FROM sys.assemblies
        WHERE is_user_defined = 1
        AND permission_set_desc != 'SAFE_ACCESS';
      }

      describe "#{db} db: 'CLR Assembly Permission Set' should be set to 'SAFE_ACCESS'. List of other permission sets" do
        subject { sql_session.query(clr_assembly_permissions_query).rows[1] }
        it { should be nil }
      end
    end
  end
end