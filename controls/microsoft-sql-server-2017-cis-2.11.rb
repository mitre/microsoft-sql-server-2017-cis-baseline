# encoding: UTF-8

control "microsoft-sql-server-2017-cis-2.11" do
  title " Ensure SQL Server is configured to use non-standard ports 
(Automated)"
  desc "If installed, a default SQL Server instance will be assigned a default port of
TCP:1433 for 
TCP/IP communication. Administrators can also manually configure named instances
to 
use TCP:1433 for communication. TCP:1433 is a widely known SQL Server port and
this 
port assignment should be changed. In a multi-instance scenario, each instance
must be 
assigned its own dedicated TCP/IP port."
  desc "rationale", "Using a non-default port helps protect the database from attacks directed to the
default 
port."
  desc "check", "Run the one of following T-SQL script: 
SELECT TOP(1) local_tcp_port FROM sys.dm_exec_connections 
WHERE local_tcp_port IS NOT NULL; 
Or 
SELECT local_tcp_port 
FROM   sys.dm_exec_connections 
WHERE  session_id = @@SPID 
If a value of 1433 is returned this is a fail."
  desc "fix", "1. In SQL Server Configuration Manager, in the console pane, expand SQL Server 
Network Configuration, expand Protocols for <InstanceName>, and then double-
click the TCP/IP protocol 
2. In the TCP/IP Properties dialog box, on the IP Addresses tab, several IP
addresses 
appear in the format IP1, IP2, up to IPAll. One of these is for the IP address
of the 
loopback adapter, 127.0.0.1. Additional IP addresses appear for each IP Address
on 
the computer. 
3. Under IPAll, change the TCP Port field from 1433 to a non-standard port or
leave 
the TCP Port field empty and set the TCP Dynamic Ports value to 0 to enable 
dynamic port assignment and then click OK. 
4. In the console pane, click SQL Server Services. 
5. In the details pane, right-click SQL Server (<InstanceName>) and then click 
Restart, to stop and restart SQL Server."
  desc "additional_information", "In the case of AWS RDS, this is only configurable during the build process."
  desc "impact", "Changing the default port will force the DAC (Dedicated Administrator
Connection) to 
listen on a random port. Also, it might make benign applications, such as
application 
firewalls, require special configuration. In general, you should set a static
port for 
consistent usage by applications, including firewalls, instead of using dynamic
ports which 
will be chosen randomly at each SQL Server start up."
  desc "default_value", "By default, default SQL Server instances listen on to TCP/IP traffic on TCP port
1433 and 
named instances use dynamic ports."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/configure-a-server-to-listen-on-a-specific-tcp-port'
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
9 Limitation and Control of Network Ports Protocols and 
Services 
 
Limitation and Control of Network Ports Protocols and Services"

  sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'))

  port_query = %{
    SELECT local_tcp_port
    FROM sys.dm_exec_connections
    WHERE session_id = @@SPID
    }

  describe 'SQL Server port' do
    subject { sql_session.query(port_query).column('local_tcp_port')[0] }
    it { should_not cmp 1433 }
  end
end