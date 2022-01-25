# encoding: UTF-8

control "microsoft-sql-server-2017-cis-3.7" do
  title "Ensure the SQL Server‚Äôs Full-Text Service Account is Not an 
Administrator (Manual)"
  desc "The service account and/or service SID used by the MSSQLFDLauncher service for a
default 
instance or MSSQLFDLauncher$<InstanceName> service for a named instance should
not be 
a member of the Windows Administrator group either directly or indirectly (via a
group). 
This also means that the account known as LocalSystem (aka NT AUTHORITY\\SYSTEM) 

should not be used for the Full-Text service as this account has higher
privileges than the 
SQL Server service requires."
  desc "rationale", "Following the principle of least privilege, the service account should have no
more 
privileges than required to do its job. For SQL Server services, the SQL Server
Setup will 
assign the required permissions directly to the service SID. No additional
permissions or 
privileges should be necessary."
  desc "check", "Verify that the service account (in case of a local or AD account) and service
SID are not 
members of the Windows Administrators group."
  desc "fix", "In the case where LocalSystem is used, use SQL Server Configuration Manager to
change 
to a less privileged account. Otherwise, remove the account or service SID from
the 
Administrators group. You may need to run the SQL Server Configuration Manager
if 
  
 
underlying permissions had been changed or if SQL Server Configuration Manager
was 
not originally used to set the service account."
  desc "impact", "The SQL Server Configuration Manager tool should always be used to change the
SQL 
Server‚Äôs service account. This will ensure that the account has the necessary
privileges. If 
the service needs access to resources other than the standard Microsoft-defined
directories 
and registry, then additional permissions may need to be granted separately to
those 
resources."
  desc "default_value", "By default, the Service Account (or Service SID) is not a member of the
Administrators 
group."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions'
  tag nist: []
  tag severity: "medium"
  tag cis_controls: " 
Controls 
Version 
Control 
IG 1 IG 2 IG 3 
v7 
4.3 Ensure the Use of Dedicated Administrative Accounts 
 
Ensure that all users with administrative account access use a dedicated or 
secondary account for elevated activities. This account should only be used for 

administrative activities and not internet browsing email or similar activities.

 
 
 
v6 
5.1 Minimize And Sparingly Use Administrative Privileges 
 
Minimize administrative privileges and only use administrative accounts when 
they are required. Implement focused auditing on the use of administrative
privileged 
functions and monitor for anomalous behavior. 
 
 
 
"
end