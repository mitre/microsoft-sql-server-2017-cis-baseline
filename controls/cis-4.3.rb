# encoding: UTF-8

control "microsoft-sql-server-2017-cis-4.3" do
  title "Ensure 'CHECK_POLICY' Option is set to 'ON' for All SQL Authenticated Logins (Automated)"
  desc "Applies the same password complexity policy used in Windows to passwords used inside SQL Server."
  desc "rationale", "Ensure SQL authenticated login passwords comply with the secure password policy
applied 
by the Windows Server Benchmark so that they cannot be easily compromised via
brute 
force attack."
  desc "check", "Use the following code snippet to determine the status of SQL Logins and if
their password 
complexity is enforced. 
SELECT name, is_disabled 
FROM sys.sql_logins 
WHERE is_policy_checked = 0; 
The is_policy_checked value of 0 indicates that the CHECK_POLICY option is OFF;
value of 1 
is ON. If is_disabled value is 1, then the login is disabled and unusable. If no
rows are 
returned then either no SQL Authenticated logins exist or they all have
CHECK_POLICY ON."
  desc "fix", "For each <login_name> found by the Audit Procedure, execute the following T-SQL 

statement: 
ALTER LOGIN [<login_name>] WITH CHECK_POLICY = ON; 
Note: In the case of AWS RDS do not perform this remediation for the Master
account."
  desc "impact", "This is a mitigating recommendation for systems which cannot follow the
recommendation 
to use only Windows Authenticated logins. 
Weak passwords can lead to compromised systems. SQL Server authenticated logins
will 
utilize the password policy set in the computer's local policy, which is
typically set by the 
Default Domain Policy setting. 
The setting is only enforced when the password is changed. This setting does not
force 
existing weak passwords to be changed."
  desc "default_value", "CHECK_POLICY is ON"
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/relational-databases/security/password-policy'
  tag nist: ['AC-2', 'IA-5 (1)']
  tag severity: "medium"
  tag cis_controls: [
    { '6' => ['16'] },
    { '7' => ['4.4'] }
  ] 

  sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'))

  sql_auth_password_policy_query = %{
    SELECT name, is_disabled FROM sys.sql_logins
    WHERE is_policy_checked = 0;
    }

  noncompliant_logins = sql_session.query(sql_auth_password_policy_query).column('name')

  describe "'CHECK_POLICY' Option" do
    it "should be set to 'ON' for All SQL Authenticated Logins." do
      failure_message = "List of SQL logins that don't comply with the Windows secure password policy: #{noncompliant_logins.join(", ")}"
      expect(noncompliant_logins).to be_empty, failure_message
    end
  end
end