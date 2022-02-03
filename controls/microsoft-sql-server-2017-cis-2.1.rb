# encoding: UTF-8

control "microsoft-sql-server-2017-cis-2.1" do
  title " Ensure Unnecessary SQL Server Protocols are set to 'Disabled' 
(Manual)"
  desc "SQL Server supports Shared Memory, Named Pipes, and TCP/IP protocols. However,
SQL 
Server should be configured to use the bare minimum required based on the
organization's 
needs."
  desc "rationale", "Using fewer protocols minimizes the attack surface of SQL Server and, in some
cases, can 
protect it from remote attacks."
  desc "check", "Open SQL Server Configuration Manager; go to the SQL Server Network
Configuration. 
Ensure that only required protocols are enabled."
  desc "fix", "Open SQL Server Configuration Manager; go to the SQL Server Network
Configuration. 
Ensure that only required protocols are enabled. Disable protocols not
necessary."
  desc "impact", "The Database Engine (MSSQL and SQLAgent) services must be stopped and restarted
for 
the change to take effect."
  desc "default_value", "By default, TCP/IP and Shared Memory protocols are enabled on all commercial
editions."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/enable-or-disable-a-server-network-protocol'
  tag nist: []
  tag severity: "medium"
  tag cis_controls: " 
 
 
Controls 
Version 
Control 
IG 1 IG 2 IG 3 
v7 
9.2 Ensure Only Approved Ports Protocols and Services 
Are Running 
 
Ensure that only network ports protocols and services listening on a system 
with validated business needs are running on each system. 
 
 
 
v6 
9.1 Limit Open Ports Protocols and Services 
 
Ensure that only ports protocols and services with validated business needs 
are running on each system."


  sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'),
    db_name: input('db_name'))

  query = %{
    SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use
    FROM sys.configurations
    WHERE name = 'Ad Hoc Distributed Queries';
    GO
    }

  describe 'Ad Hoc Distributed Queries' do
    subject { sql_session.query(query).rows[0] }
    its('value_configured') { should cmp 0 }
    its('value_in_use') { should cmp 0 }
  end

end