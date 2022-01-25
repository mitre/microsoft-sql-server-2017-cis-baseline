# encoding: UTF-8

control "microsoft-sql-server-2017-cis-2.12" do
  title " Ensure 'Hide Instance' option is set to 'Yes' for Production SQL 
Server instances (Automated)"
  desc "Non-clustered SQL Server instances within production environments should be
designated 
as hidden to prevent advertisement by the SQL Server Browser service."
  desc "rationale", "Designating production SQL Server instances as hidden leads to a more secure
installation 
because they cannot be enumerated. However, clustered instances may break if
this option 
is selected."
  desc "check", "Perform either the GUI or T-SQL method shown: 
1.1.1.1 GUI Method 
 
1. In SQL Server Configuration Manager, expand SQL Server Network 
Configuration, right-click Protocols for <InstanceName>, and then select 
Properties. 
2. On the Flags tab, in the Hide Instance box, if Yes is selected, it is
compliant. 
1.1.1.2 T-SQL Method 
 
Execute the following T-SQL. 
  
 
DECLARE @getValue INT; 
EXEC master.sys.xp_instance_regread 
      @rootkey = N'HKEY_LOCAL_MACHINE', 
      @key = N'SOFTWARE\\Microsoft\\Microsoft SQL 
Server\\MSSQLServer\\SuperSocketNetLib', 
      @value_name = N'HideInstance', 
      @value = @getValue OUTPUT; 
SELECT @getValue; 
A value of 1 should be returned to be compliant."
  desc "fix", "Perform either the GUI or T-SQL method shown: 
1.1.1.3 GUI Method 
 
1. In SQL Server Configuration Manager, expand SQL Server Network 
Configuration, right-click Protocols for <InstanceName>, and then select 
Properties. 
2. On the Flags tab, in the Hide Instance box, select Yes, and then click OK to
close the 
dialog box. The change takes effect immediately for new connections. 
1.1.1.4 T-SQL Method 
 
Execute the following T-SQL to remediate: 
EXEC master.sys.xp_instance_regwrite 
      @rootkey = N'HKEY_LOCAL_MACHINE', 
      @key = N'SOFTWARE\\Microsoft\\Microsoft SQL 
Server\\MSSQLServer\\SuperSocketNetLib', 
      @value_name = N'HideInstance', 
      @type = N'REG_DWORD', 
      @value = 1;"
  desc "impact", "This method only prevents the instance from being listed on the network. If the
instance is 
hidden (not exposed by SQL Browser), then connections will need to specify the
server and 
port in order to connect. It does not prevent users from connecting to server if
they know 
the instance name and port. 
If you hide a clustered named instance, the cluster service may not be able to
connect to the 
SQL Server. Please refer to the Microsoft documentation reference."
  desc "default_value", "By default, SQL Server instances are not hidden."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/hide-an-instance-of-sql-server-database-engine'
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
 
Limitation and Control of Network Ports Protocols and Services 
 
 
 
"
end