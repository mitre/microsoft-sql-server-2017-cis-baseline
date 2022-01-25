# encoding: UTF-8

control "microsoft-sql-server-2017-cis-7.2" do
  title "Ensure Asymmetric Key Size is set to 'greater than or equal to 2048' 
in non-system databases (Automated)"
  desc "Microsoft Best Practices recommend to use at least a 2048-bit encryption
algorithm for 
asymmetric keys."
  desc "rationale", "The RSA_2048 encryption algorithm for asymmetric keys in SQL Server is the
highest bit-
level provided and therefore the most secure available choice (other choices are
RSA_512 
and RSA_1024)."
  desc "check", "Run the following code for each individual user database: 
USE <database_name> 
GO 
SELECT db_name() AS Database_Name, name AS Key_Name 
FROM sys.asymmetric_keys 
WHERE key_length < 2048 
AND db_id() > 4; 
GO 
For compliance, no rows should be returned."
  desc "fix", "Refer to Microsoft SQL Server Books Online ALTER ASYMMETRIC KEY entry: 
https://docs.microsoft.com/en-us/sql/t-sql/statements/alter-asymmetric-key-transact-

sql"
  desc "impact", "The higher-bit level may result in slower performance, but reduces the
likelihood of an 
attacker breaking the key. 
Encrypted data cannot be compressed, but compressed data can be encrypted. If
you use 
compression, you should compress data before encrypting it."
  desc "default_value", "None"
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/t-sql/statements/alter-asymmetric-key-transact-sql'
  ref 'http://support.microsoft.com/kb/2162020'
  tag nist: []
  tag severity: "medium"
  tag cis_controls: " 
Controls 
Version 
Control 
IG 1 IG 2 IG 3 
v7 
14.4 Encrypt All Sensitive Information in Transit 
 
Encrypt all sensitive information in transit. 
 
 
 
v6 
14.2 Encrypt All Sensitive Information Over Less-trusted 
Networks 
 
All communication of sensitive information over less-trusted networks should be 

encrypted. Whenever information flows over a network with a lower trust level
the 
information should be encrypted. 
 
 
 
"
end