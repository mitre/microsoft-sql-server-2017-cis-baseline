# encoding: UTF-8

control "microsoft-sql-server-2017-cis-1.2" do
  title "Ensure Single-Function Member Servers are Used (Manual)"
  desc "It is recommended that SQL Server software be installed on a dedicated server.
This 
architectural consideration affords security flexibility in that the database
server can be 
placed on a separate subnet allowing access only from particular hosts and over
particular 
protocols. Degrees of availability are easier to achieve as well - over time, an
enterprise can 
move from a single database server to a failover to a cluster using load
balancing or to 
some combination thereof."
  desc "rationale", "It is easier to manage (i.e. reduce) the attack surface of the server hosting
SQL Server 
software if the only surfaces to consider are the underlying operating system,
SQL Server 
itself, and any security/operational tooling that may additionally be installed.
As noted in 
the description, availability can be more easily addressed if the database is on
a dedicated 
server."
  desc "check", "Ensure that no other roles are enabled for the underlying operating system and
that no 
excess tooling is installed, per enterprise policy."
  desc "fix", "Uninstall excess tooling and/or remove unnecessary roles from the underlying
operating 
system."
  desc "impact", "It is difficult to see any reasonably adverse impact to making this
architectural change, 
once the costs of making the change have been paid. Custom applications may need
to be 
modified to accommodate database connections over the wire rather than on the
host (i.e. 
using TCP/IP instead of Named Pipes). Additional hardware and operating system
licenses 
may be required to make these architectural changes."
  impact 0.5
  tag nist: ['SI-10', 'SC-32']
  tag severity: "medium"
  tag cis_controls: [
    { '6' => ['9.6'] },
    { '7' => ['2.10'] }
  ]

  describe 'SQL Server software should be installed on a dedicated server.' do
    skip 'This control requires a manual review to ensure that SQL Server software is installed on a dedicated server.'
  end
end