# encoding: UTF-8

control "microsoft-sql-server-2017-cis-1.1" do
  title "Ensure Latest SQL Server Cumulative and Security Updates are 
Installed (Manual)"
  desc "SQL Server patches contain program updates that fix security and product
functionality 
issues found in the software. These patches can be installed with a security
update, which is 
a single patch, or a cumulative update which is a group of patches. The SQL
Server version 
and patch levels should be the most recent compatible with the organizations'
operational 
needs."
  desc "rationale", "Using the most recent SQL Server software, along with all applicable patches can
help limit 
the possibilities for vulnerabilities in the software. The installation version
and/or patches 
applied during setup should be established according to the needs of the
organization."
  desc "check", "To determine your SQL Server patch level, run the following code snippet. 
SELECT SERVERPROPERTY('ProductLevel') as SP_installed, 
SERVERPROPERTY('ProductVersion') as Version;"
  desc "fix", "Identify the current version and patch level of your SQL Server instances and
ensure they 
contain the latest security fixes. Make sure to test these fixes in your test
environments 
before updating production instances. 
The most recent SQL Server patches can be found here: 
  
 
https://docs.microsoft.com/en-us/sql/database-engine/install-windows/latest-updates-for-microsoft-sql-server?view=sql-server-2017"
  desc "default_value", "Cumulative and security updates are not installed by default."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/database-engine/install-windows/latest-updates-for-microsoft-sql-server?view=sql-server-2017'
  ref 'https://support.microsoft.com/en-us/help/4041553/sql-server-service-packs-are-discontinued-starting-from-sql-server'
  tag nist: ['RA-5', 'CM-7 (5)']
  tag severity: "medium"
  tag cis_controls: [
    { '6' => ['4'] },
    { '7' => ['2.2'] }
  ] 

  sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'))

  query = %{
    SELECT SERVERPROPERTY('ProductLevel') as SP_installed,
    SERVERPROPERTY('ProductVersion') as Version;
    GO
    }

  describe "SQL Version" do
    subject { sql_session.query(query).rows[0] }
    its('version') { should cmp >= input('approved_sql_version') }
  end
end