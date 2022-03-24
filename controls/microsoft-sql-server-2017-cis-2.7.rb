# encoding: UTF-8

control "microsoft-sql-server-2017-cis-2.7" do
  title "Ensure 'Remote Admin Connections' Server Configuration Option is 
set to '0' (Automated)"
  desc "The remote admin connections option controls whether a client application on a
remote 
computer can use the Dedicated Administrator Connection (DAC)."
  desc "rationale", "The Dedicated Administrator Connection (DAC) lets an administrator access a
running 
server to execute diagnostic functions or Transact-SQL statements, or to
troubleshoot 
problems on the server, even when the server is locked or running in an abnormal
state 
and not responding to a SQL Server Database Engine connection. In a cluster
scenario, the 
administrator may not actually be logged on to the same node that is currently
hosting the 
SQL Server instance and thus is considered \"remote\". Therefore, this setting
should usually 
be enabled (1) for SQL Server failover clusters; otherwise, it should be
disabled (0) which is 
the default."
  desc "check", "Run the following T-SQL command: 
USE master; 
GO 
SELECT name,  
 
CAST(value as int) as value_configured, 
 
CAST(value_in_use as int) as value_in_use 
FROM sys.configurations 
WHERE name = 'remote admin connections' 
AND SERVERPROPERTY('IsClustered') = 0; 
If no data is returned, the instance is a cluster and this recommendation is not
applicable. If 
data is returned, then both the value columns must show 0 to be compliant."
  desc "fix", "Run the following T-SQL command on non-clustered installations: 
  
 
EXECUTE sp_configure 'remote admin connections', 0; 
RECONFIGURE; 
GO"
  desc "additional_information", "If it's a clustered installation, this option must be enabled as a clustered SQL
Server cannot 
bind to localhost and DAC will be unavailable otherwise. Enable it for clustered

installations. Disable it for standalone installations where not required."
  desc "default_value", "By default, this option is disabled (0), only local connections may use the DAC."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/remote-admin-connections-server-configuration-option'
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
    port: input('port'))

  remote_admin_connections_query = %{
    SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use
    FROM sys.configurations
    WHERE name = 'remote admin connections'
    AND SERVERPROPERTY('IsClustered') = 0;
  }

  describe "Remote Admin Connections option should be disabled on standalone installations." do
    subject { sql_session.query(remote_admin_connections_query).rows[0] }
    its('value_configured') { should cmp 0 }
    its('value_in_use') { should cmp 0 }
  end
end