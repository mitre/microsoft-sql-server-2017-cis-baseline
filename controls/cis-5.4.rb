# encoding: UTF-8

control "microsoft-sql-server-2017-cis-5.4" do
  title "Ensure 'SQL Server Audit' is set to capture both 'failed' and 'successful logins' (Automated)"
  desc "SQL Server Audit is capable of capturing both failed and successful logins and
writing them 
to one of three places: the application event log, the security event log, or
the file system. 
We will use it to capture any login attempt to SQL Server, as well as any
attempts to change 
audit policy. This will also serve to be a second source to record failed login
attempts."
  desc "rationale", "By utilizing Audit instead of the traditional setting under the Security tab to
capture 
successful logins, we reduce the noise in the ERRORLOG. This keeps it smaller
and easier to 
read for DBAs who are attempting to troubleshoot issues with the SQL Server.
Also, the 
Audit object can write to the security event log, though this requires operating
system 
configuration. This gives an additional option for where to store login events,
especially in 
conjunction with an SIEM."
  desc "check", "SELECT  
 S.name AS 'Audit Name' 
 , CASE S.is_state_enabled 
 WHEN 1 THEN 'Y' 
 WHEN 0 THEN 'N' END AS 'Audit Enabled' 
 , S.type_desc AS 'Write Location' 
 , SA.name AS 'Audit Specification Name' 
 , CASE SA.is_state_enabled 
 WHEN 1 THEN 'Y' 
 WHEN 0 THEN 'N' END AS 'Audit Specification Enabled' 
 , SAD.audit_action_name 
 , SAD.audited_result 
FROM sys.server_audit_specification_details AS SAD 
  
 
 JOIN sys.server_audit_specifications AS SA 
 ON SAD.server_specification_id = SA.server_specification_id 
 JOIN sys.server_audits AS S 
 ON SA.audit_guid = S.audit_guid 
WHERE SAD.audit_action_id IN ('CNAU', 'LGFL', 'LGSD'); 
The result set should contain 3 rows, one for each of the following
audit_action_names: 
- AUDIT_CHANGE_GROUP 
- FAILED_LOGIN_GROUP 
- SUCCESSFUL_LOGIN_GROUP 
Both the Audit and Audit specification should be enabled and the audited_result
should 
include both success and failure."
  desc "fix", "Perform either the GUI or T-SQL method shown: 
1.1.1.13 GUI Method 
 
1. Expand the SQL Server in Object Explorer. 
2. Expand the Security Folder 
3. Right-click on the Audits folder and choose New Audit... 
4. Specify a name for the Server Audit. 
5. Specify the audit destination details and then click OK to save the Server
Audit. 
6. Right-click on Server Audit Specifications and choose New Server Audit 
Specification... 
7. Name the Server Audit Specification 
8. Select the just created Server Audit in the Audit drop-down selection. 
9. Click the drop-down under Audit Action Type and select AUDIT_CHANGE_GROUP. 
10. Click the new drop-down Audit Action Type and select FAILED_LOGIN_GROUP. 
11. Click the new drop-down under Audit Action Type and select 
SUCCESSFUL_LOGIN_GROUP. 
12. Click OK to save the Server Audit Specification. 
13. Right-click on the new Server Audit Specification and select Enable Server
Audit 
Specification. 
14. Right-click on the new Server Audit and select Enable Server Audit. 
1.1.1.14 T-SQL Method 
 
Execute code similar to: 
  
 
CREATE SERVER AUDIT TrackLogins 
TO APPLICATION_LOG; 
GO 
CREATE SERVER AUDIT SPECIFICATION TrackAllLogins 
FOR SERVER AUDIT TrackLogins 
  ADD (FAILED_LOGIN_GROUP), 
  ADD (SUCCESSFUL_LOGIN_GROUP), 
  ADD (AUDIT_CHANGE_GROUP) 
WITH (STATE = ON); 
GO 
ALTER SERVER AUDIT TrackLogins 
WITH (STATE = ON); 
GO 
Note: If the write destination for the Audit object is to be the security event
log, see the 
Books Online topic Write SQL Server Audit Events to the Security Log and follow
the 
appropriate steps."
  desc "impact", "With the previous recommendation, only failed logins are captured. If the Audit
object is 
not implemented with the appropriate setting, SQL Server will not capture
successful 
logins, which might prove of use for forensics."
  desc "default_value", "By default, there are no audit object tracking login events."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/relational-databases/security/auditing/create-a-server-audit-and-server-audit-specification'
  tag nist: ['AU-2']
  tag severity: "medium"
  tag cis_controls: [
    { '6' => ['5.5'] },
    { '7' => ['4.9'] }
  ]

  sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'))
  
  sql_server_audit_query = %{
    SELECT S.name AS 'Audit Name', CASE S.is_state_enabled
    WHEN 1 THEN 'Y'
    WHEN 0 THEN 'N' END AS 'Audit Enabled', S.type_desc AS 'Write Location', SA.name AS 'Audit Specification Name', CASE SA.is_state_enabled
    WHEN 1 THEN 'Y'
    WHEN 0 THEN 'N' END AS 'Audit Specification Enabled' , SAD.audit_action_name, SAD.audited_result
    FROM sys.server_audit_specification_details AS SAD
    JOIN sys.server_audit_specifications AS SA
    ON SAD.server_specification_id = SA.server_specification_id JOIN sys.server_audits AS S
    ON SA.audit_guid = S.audit_guid
    WHERE SAD.audit_action_id IN ('CNAU', 'LGFL', 'LGSD');
  }

  if sql_session.query(sql_server_audit_query).rows[0] == nil
    describe "'SQL Server Audit'" do
      it "should be set to capture both 'failed' and 'successful logins'." do
        failure_message = "No audit actions found."
        expect(sql_session.query(sql_server_audit_query).rows[0]).not_to be_nil, failure_message
      end
    end
  else
    describe "Audit action for Audit Change Group should be enabled. Value for" do
      subject { sql_session.query(sql_server_audit_query).rows[0] }
      its("audit_action_name") { should cmp "AUDIT_CHANGE_GROUP" }
      its("audit enabled") { should cmp "Y" }
      its("audit specification enabled") { should cmp "Y" }
      its("audited_result") { should cmp "SUCCESS AND FAILURE" }
    end

    describe "Audit action for Failed Login Group should be enabled. Value for" do
      subject { sql_session.query(sql_server_audit_query).rows[1] }
      its("audit_action_name") { should cmp "FAILED_LOGIN_GROUP" }
      its("audit enabled") { should cmp "Y" }
      its("audit specification enabled") { should cmp "Y" }
      its("audited_result") { should cmp "SUCCESS AND FAILURE" }
    end

    describe "Audit action for Successful Login Group should be enabled. Value for" do
      subject { sql_session.query(sql_server_audit_query).rows[2] }
      its("audit_action_name") { should cmp "SUCCESSFUL_LOGIN_GROUP" }
      its("audit enabled") { should cmp "Y" }
      its("audit specification enabled") { should cmp "Y" }
      its("audited_result") { should cmp "SUCCESS AND FAILURE" }
    end
  end
end