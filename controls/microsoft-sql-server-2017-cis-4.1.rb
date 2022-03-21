# encoding: UTF-8

control "microsoft-sql-server-2017-cis-4.1" do
  title "Ensure 'MUST_CHANGE' Option is set to 'ON' for All SQL Authenticated Logins (Manual)"
  desc "Whenever this option is set to ON, SQL Server will prompt for an updated
password the first 
time the new or altered login is used."
  desc "rationale", "Enforcing a password change after a reset or new login creation will prevent the
account 
administrators or anyone accessing the initial password from misuse of the SQL
login 
created without being noticed."
  desc "check", "1. Open SQL Server Management Studio. 
2. Open Object Explorer and connect to the target instance. 
3. Navigate to the Logins tab in Object Explorer and expand. Right click on the 

desired login and select Properties. 
4. Verify the User must change password at next login checkbox is checked. 
Note: This audit procedure is only applicable immediately after the login has
been created 
or altered to force the password change. Once the password is changed, there is
no way to 
know specifically that this option was the forcing mechanism behind a password
change."
  desc "fix", "Set the MUST_CHANGE option for SQL Authenticated logins when creating a login
initially: 
  
 
CREATE LOGIN <login_name> WITH PASSWORD = '<password_value>' MUST_CHANGE, 
CHECK_EXPIRATION = ON, CHECK_POLICY = ON; 
Set the MUST_CHANGE option for SQL Authenticated logins when resetting a
password: 
ALTER LOGIN <login_name> WITH PASSWORD = '<new_password_value>' MUST_CHANGE;"
  desc "impact", "CHECK_EXPIRATION and CHECK_POLICY options must both be ON. End users must have
the 
means (application) to change the password when forced."
  desc "default_value", "ON when creating a new login via the SSMS GUI. OFF when creating a new login
using T-SQL 
CREATE LOGIN unless the MUST_CHANGE option is explicitly included along with 
CHECK_EXPIRATION = ON."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/t-sql/statements/alter-login-transact-sql'
  ref 'https://docs.microsoft.com/en-us/sql/t-sql/statements/create-login-transact-sql'
  tag nist: []
  tag severity: "medium"
  tag cis_controls: " 
Controls 
Version 
Control 
IG 1 IG 2 IG 3 
v7 
4.2 Change Default Passwords 
 
Before deploying any new asset change all default passwords to have values 
consistent with administrative level accounts. 
 
 
 
v6 
16 Account Monitoring and Control 
 
Account Monitoring and Control"

  describe "Ensure 'MUST_CHANGE' Option is set to 'ON' for All SQL Authenticated Logins." do
    skip "This control requires a manual review to ensure that 'MUST_CHANGE' Option is set to 'ON' for All SQL Authenticated Logins."
  end
end