# encoding: UTF-8

control "microsoft-sql-server-2017-cis-7.1" do
  title "Ensure 'Symmetric Key encryption algorithm' is set to 'AES_128' or 
higher in non-system databases (Automated)"
  desc "Per the Microsoft Best Practices, only the SQL Server AES algorithm options,
AES_128, 
AES_192, and AES_256, should be used for a symmetric key encryption algorithm."
  desc "rationale", "The following algorithms (as referred to by SQL Server) are considered weak or
deprecated 
and should no longer be used in SQL Server: DES, DESX, RC2, RC4, RC4_128. 
Many organizations may accept the Triple DES algorithms (TDEA) which use keying
options 
1 (3 key aka 3TDEA) or keying option 2 (2 key aka 2TDEA). In SQL Server, these
are referred 
to as TRIPLE_DES_3KEY and TRIPLE_DES respectively. Additionally, the SQL Server 

algorithm named DESX is actually the same implementation as the TRIPLE_DES_3KEY 

option. However, using the DESX identifier as the algorithm type has been
deprecated and 
its usage is now discouraged."
  desc "check", "Run the following code for each individual user database: 
USE <database_name> 
GO 
  
 
SELECT db_name() AS Database_Name, name AS Key_Name 
FROM sys.symmetric_keys 
WHERE algorithm_desc NOT IN ('AES_128','AES_192','AES_256') 
AND db_id() > 4; 
GO 
For compliance, no rows should be returned."
  desc "fix", "Refer to Microsoft SQL Server Books Online ALTER SYMMETRIC KEY entry: 
https://docs.microsoft.com/en-us/sql/t-sql/statements/alter-symmetric-key-transact-sql"
  desc "impact", "Eliminates use of weak and deprecated algorithms which may put a system at
higher risk of 
an attacker breaking the key. 
Encrypted data cannot be compressed, but compressed data can be encrypted. If
you use 
compression, you should compress data before encrypting it."
  desc "default_value", "none"
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/t-sql/statements/alter-symmetric-key-transact-sql'
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
information should be encrypted."

  sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'))

  get_all_dbs_query = %{
  SELECT name FROM master.sys.databases;
  GO
  }

  databases = sql_session.query(get_all_dbs_query).column('name')

  databases.each do |db| # map - when passes outnumber failures
    unless input('excluded_dbs').include? db

      encryption_algorithm_query = %{
        USE #{db};
        GO
        SELECT db_name() AS Database_Name, name AS Key_Name
        FROM sys.symmetric_keys
        WHERE algorithm_desc NOT IN ('AES_128','AES_192','AES_256') AND db_id() > 4;
        GO
      }

      describe "#{db} db: 'Symmetric Key encryption algorithm' should be set to 'AES_128' or higher. List of other algorithms" do
        subject { sql_session.query(encryption_algorithm_query).rows[1] }
        it { should be nil }
      end
    end
  end
end