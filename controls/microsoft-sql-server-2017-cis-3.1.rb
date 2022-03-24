# encoding: UTF-8

control "microsoft-sql-server-2017-cis-3.1" do
  title "Ensure 'Server Authentication' Property is set to 'Windows Authentication Mode' (Automated)"
  desc "Uses Windows Authentication to validate attempted connections."
  desc "rationale", "Windows provides a more robust authentication mechanism than SQL Server authentication."
  desc "check", "Execute the following syntax:
  SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') as [login_mode];

  A login_mode of 1 indicates the Server Authentication property is set to Windows Authentication Mode. A login_mode of 0 indicates mixed mode authentication."
  desc "fix", "Perform either the GUI or T-SQL method shown:

  1.1.1.5 GUI Method
  1. Open SQL Server Management Studio.
  2. Open the Object Explorer tab and connect to the target database instance.
  3. Right click the instance name and select Properties.
  4. Select the Security page from the left menu.
  5. Set the Server authentication setting to Windows Authentication Mode.

  1.1.1.6 T-SQL Method
  Run the following T-SQL in a Query Window:
  USE [master]
  GO
  EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\\Microsoft\\MSSQLServer\\MSSQLServer', N'LoginMode', REG_DWORD, 1 GO
  
  Restart the SQL Server service for the change to take effect."
  desc "impact", "Changing the login mode configuration requires a restart of the service."
  desc "default_value", "Windows Authentication Mode"
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/server-properties-security-page'
  tag nist: []
  tag severity: "medium"
  tag cis_controls: " 
  Controls Version
  Control
  IG 1
  IG 2
  IG 3
  
  v7
  16.2 Configure Centralized Point of Authentication Configure access for all accounts through as few centralized points of
  authentication as possible, including network, security, and cloud systems.
    
  
  v6
  16.9 Configure Account Access Centrally
  Configure access for all accounts through a centralized point of authentication, for
  example Active Directory or LDAP. Configure network and security devices for centralized authentication as well."

  sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'))

  login_mode_query = %{
    SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') as [login_mode];
    }

  describe 'Windows Authentication Mode should be used for server authentication.' do
    subject { sql_session.query(login_mode_query).rows[0] }
    its('login_mode') { should cmp 1 }
  end
end