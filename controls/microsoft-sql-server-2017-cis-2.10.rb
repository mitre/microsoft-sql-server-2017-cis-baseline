# encoding: UTF-8

control "microsoft-sql-server-2017-cis-2.10" do
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
  tag nist: ['CM-7 (1)']
  tag severity: "medium"
  tag cis_controls: [
    { '6' => ['9.1'] },
    { '7' => ['9.2'] }
  ]

  describe 'Unnecessary SQL Server Protocols should be disabled.' do
    skip 'This control requires a manual review to ensure that unnecessary SQL Server Protocols are set to be disabled.'
  end
end