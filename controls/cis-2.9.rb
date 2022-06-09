# encoding: UTF-8

control "microsoft-sql-server-2017-cis-2.9" do
  title "Ensure 'Trustworthy' Database Property is set to 'Off' (Automated)"
  desc "The TRUSTWORTHY database option allows database objects to access objects in
other 
databases under certain circumstances."
  desc "rationale", "Provides protection from malicious CLR assemblies or extended procedures."
  desc "check", "Run the following T-SQL query to list any databases with a Trustworthy database
property 
value of ON: 
SELECT name 
FROM sys.databases 
WHERE is_trustworthy_on = 1 
AND name != 'msdb'; 
No rows should be returned."
  desc "fix", "Execute the following T-SQL statement against the databases (replace
<database_name> 
below) returned by the Audit Procedure: 
ALTER DATABASE [<database_name>] SET TRUSTWORTHY OFF;"
  desc "default_value", "By default, this database property is OFF (is_trustworthy_on = 0), except for
the msdb 
database in which it is required to be ON."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/relational-databases/security/trustworthy-database-property'
  ref 'https://support.microsoft.com/it-it/help/2183687/guidelines-for-using-the-trustworthy-database-setting-in-sql-server'
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

  trustworthy_db_query = %{
    SELECT name
    FROM sys.databases;
    WHERE is_trustworthy_on = 1;
    AND name != 'msdb';
  }

  describe "Trustworthy databases" do
    subject { sql_session.query(trustworthy_db_query).column('name') }
    it { should be_empty }
  end
end