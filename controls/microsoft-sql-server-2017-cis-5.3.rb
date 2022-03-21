# encoding: UTF-8

control "microsoft-sql-server-2017-cis-5.3" do
  title "Ensure 'Login Auditing' is set to 'failed logins' (Automated)"
  desc "This setting will record failed authentication attempts for SQL Server logins to
the SQL 
Server Errorlog. This is the default setting for SQL Server. 
Historically, this setting has been available in all versions and editions of
SQL Server. Prior 
to the availability of SQL Server Audit, this was the only provided mechanism
for 
capturing logins (successful or failed)."
  desc "rationale", "Capturing failed logins provides key information that can be used to
detect\\confirm 
password guessing attacks. Capturing successful login attempts can be used to
confirm 
server access during forensic investigations, but using this audit level setting
to also 
capture successful logins creates excessive noise in the SQL Server Errorlog
which can 
hamper a DBA trying to troubleshoot problems. Elsewhere in this benchmark, we 
recommend using the newer lightweight SQL Server Audit feature to capture both 
successful and failed logins."
  desc "check", "EXEC xp_loginconfig 'audit level';   
A config_value of failure indicates a server login auditing setting of Failed
logins only. 
If a config_value of all appears, then both failed and successful logins are
being logged. 
Both settings should also be considered valid, but as mentioned capturing
successful logins 
using this method creates lots of noise in the SQL Server Errorlog."
  desc "fix", "Perform either the GUI or T-SQL method shown: 
1.1.1.11 GUI Method 
 
1. Open SQL Server Management Studio. 
2. Right click the target instance and select Properties and navigate to the
Security 
tab. 
3. Select the option Failed logins only under the Login Auditing section and
click OK. 
4. Restart the SQL Server instance. 
1.1.1.12 T-SQL Method 
 
1. Run: 
EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', 
N'Software\\Microsoft\\MSSQLServer\\MSSQLServer', N'AuditLevel', 
REG_DWORD, 2 
2. Restart the SQL Server instance."
  desc "impact", "At a minimum, we want to ensure failed logins are captured in order to detect if
an 
adversary is attempting to brute force passwords or otherwise attempting to
access a SQL 
Server improperly. 
Changing the setting requires a restart of the SQL Server service."
  desc "default_value", "By default, only failed login attempts are captured."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/server-properties-security-page'
  tag nist: []
  tag severity: "medium"
  tag cis_controls: " 
Controls 
Version 
Control 
IG 1 IG 2 IG 3 
v7 
16.13 Alert on Account Login Behavior Deviation 
 
Alert when users deviate from normal login behavior such as time-of-day 
workstation location and duration. 
 
 
 
v6 
16.10 Profile User Account Usage And Monitor For Anomalies 
 
Profile each user s typical account usage by determining normal time-of-day
access 
and access duration. Reports should be generated that indicate users who have
logged 
in during unusual hours or have exceeded their normal login duration. This
includes 
 
 
 
 
 
Controls 
Version 
Control 
IG 1 IG 2 IG 3 
flagging the use of the user s credentials from a computer other than computers
on 
which the user generally works."

  sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'))

  login_auditing_query = %{
    EXEC xp_loginconfig 'audit level';
  }
  describe.one do
    describe "'Login Auditing' should capture at least login failures." do
      subject { sql_session.query(login_auditing_query).rows[0] }
      its('config_value') { should cmp "failure" }
    end
    describe "'Login Auditing' should capture at least login failures." do
      subject { sql_session.query(login_auditing_query).rows[0] }
      its('config_value') { should cmp "all" }
    end
  end
end