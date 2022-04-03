# encoding: UTF-8

control "microsoft-sql-server-2017-cis-3.11" do
  title "Ensure the public role in the msdb database is not granted access 
to SQL Agent proxies (Automated)"
  desc "The public database role contains every user in the msdb database. SQL Agent
proxies 
define a security context in which a job step can run."
  desc "rationale", "Granting access to SQL Agent proxies for the public role would allow all users
to utilize the 
proxy which may have high privileges. This would likely break the principle of
least 
privileges."
  desc "check", "Use the following syntax to determine if access to any proxies have been granted
to the 
msdb database's public role. 
USE [msdb] 
GO 
SELECT sp.name AS proxyname 
FROM dbo.sysproxylogin spl 
JOIN sys.database_principals dp 
ON dp.sid = spl.sid 
JOIN sysproxies sp 
ON sp.proxy_id = spl.proxy_id 
WHERE principal_id = USER_ID('public'); 
GO 
This query should not return any rows."
  desc "fix", "1. Ensure the required security principals are explicitly granted access to the
proxy 
(use sp_grant_login_to_proxy). 
  
 
2. Revoke access to the <proxyname> from the public role. 
USE [msdb] 
GO 
EXEC dbo.sp_revoke_login_from_proxy @name = N'public', @proxy_name = 
N'<proxyname>'; 
GO"
  desc "impact", "Before revoking the public role from the proxy, ensure that alternative logins
or 
appropriate user-defined database roles have been added with equivalent
permissions. 
Otherwise, SQL Agent job steps dependent upon this access will fail."
  desc "default_value", "By default, the msdb public database role does not have access to any proxy."
  impact 0.5
  ref 'https://support.microsoft.com/en-us/help/2160741/best-practices-in-configuring-sql-server-agent-proxy-account'
  tag nist: ['AC-3 (3)']
  tag severity: "medium"
  tag cis_controls: [
    { '6' => ['14.4'] },
    { '7' => ['14.6'] }
  ] 

  sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'),
    db_name: 'msdb')

  msdb_public_proxy_query = %{
    SELECT sp.name AS proxy_name
    FROM dbo.sysproxylogin spl
    JOIN sys.database_principals dp
    ON dp.sid = spl.sid
    JOIN sysproxies sp
    ON sp.proxy_id = spl.proxy_id
    WHERE principal_id = USER_ID('public');
    }

  msb_public_proxies = sql_session.query(msdb_public_proxy_query).column('proxy_name')

  describe "Public role in the msdb db" do
    it "should not be granted access to SQL Agent proxies." do
      failure_message = "Access to these proxies should not be given to the public role: #{msb_public_proxies.join(", ")}"
      expect(msb_public_proxies).to be_empty, failure_message
    end
  end
end