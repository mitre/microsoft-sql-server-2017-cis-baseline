# encoding: UTF-8

control "microsoft-sql-server-2017-cis-2.14" do
  title "Ensure the 'sa' Login Account has been renamed (Automated)"
  desc "The sa account is a widely known and often widely used SQL Server login with
sysadmin 
privileges. The sa login is the original login created during installation and
always has 
principal_id=1 and sid=0x01."
  desc "rationale", "It is more difficult to launch password-guessing and brute-force attacks against
the sa login 
if the name is not known."
  desc "check", "Use the following syntax to determine if the sa login (principal) is renamed. 
SELECT name 
FROM sys.server_principals 
WHERE sid = 0x01; 
A name of sa indicates the account has not been renamed and therefore needs
remediation."
  desc "fix", "Replace the <different_user> value within the below syntax and execute to rename
the sa 
login. 
ALTER LOGIN sa WITH NAME = <different_user>;"
  desc "additional_information", "In the case of AWS RDS the default name for this account is rdsa instead of sa."
  desc "impact", "It is not a good security practice to code applications or scripts to use the sa
login. 
However, if this has been done, renaming the sa login will prevent scripts and
applications 
from authenticating to the database server and executing required tasks or
functions."
  desc "default_value", "By default, the sa login name is 'sa'."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode'
  tag nist: ['AC-6', 'CM-6']
  tag severity: "medium"
  tag cis_controls: [
    { '6' => ['5'] },
    { '7' => ['5.1'] }
  ]
  
  sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'))

  original_account_query = %{
    SELECT name FROM sys.server_principals
    WHERE sid = 0x01;
    }

  sysadmin = sql_session.query(original_account_query).rows[0].name

  describe 'The original login account' do
    it "should be renamed." do
      failure_message = "The '#{sysadmin}' login account needs to be renamed to something other than 'sa'."
      expect(sysadmin).not_to eq('sa'), failure_message
    end
  end
end