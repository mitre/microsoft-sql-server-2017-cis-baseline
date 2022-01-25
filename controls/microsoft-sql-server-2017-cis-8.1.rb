# encoding: UTF-8

control "microsoft-sql-server-2017-cis-8.1" do
  title "Ensure 'SQL Server Browser Service' is configured correctly (Manual)"
  desc "No recommendation is being given on disabling the SQL Server Browser service."
  desc "rationale", "In the case of a default instance installation, the SQL Server Browser service
is disabled by 
default. Unless there is a named instance on the same server, there is typically
no reason 
for the SQL Server Browser service to be running. In this case it is strongly
suggested that 
the SQL Server Browser service remain disabled. 
When it comes to named instances, given that a security scan can fingerprint a
SQL Server 
listening on any port, it's therefore of limited benefit to disable the SQL
Server Browser 
service. 
However, if all connections against the named instance are via applications and
are not 
visible to end users, then configuring the named instance to listening on a
static port, 
disabling the SQL Server Browser service, and configuring the apps to connect to
the 
specified port should be the direction taken. This follows the general practice
of reducing 
the surface area, especially for an unneeded feature. 
On the other hand, if end users are directly connecting to databases on the
instance, then 
typically having them use ServerName\\InstanceName is best. This requires the SQL
Server 
Browser service to be running. Disabling the SQL Server Browser service would
mean the 
end users would have to remember port numbers for the instances. When they don't
that 
will generate service calls to IT staff. Given the limited benefit of disabling
the service, the 
trade-off is probably not worth it, meaning it makes more business sense to
leave the SQL 
Server Browser service enabled."
  desc "check", "Check the SQL Browser service's status via services.msc or similar methods."
  desc "fix", "Enable or disable the service as needed for your environment."
  desc "default_value", "The SQL Server Browser service is disabled if only a default instance is
installed on the 
server. If a named instance is installed, the default value is for the SQL
Server Browser 
service to be configured as Automatic for startup."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/sql-server-browser-service-database-engine-and-ssas'
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
are running on each system. 
 
 
 
 
 
"
end