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
  tag nist: ['SC-8']
  tag severity: "medium"
  tag cis_controls: [
    { '6' => ['14.2'] },
    { '7' => ['14.4'] }
  ] 

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

  databases.each do |db|
  
    sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'),
    db_name: db)

    encryption_usage_query = %{
      SELECT db_name() AS Database_Name, name AS Key_Name
      FROM sys.asymmetric_keys
    }

    encryption_usage = sql_session.query(encryption_usage_query).column('key_name')

    asymmetric_key_size_query = %{
      SELECT db_name() AS Database_Name, name AS Key_Name
      FROM sys.asymmetric_keys
      WHERE key_length < 2048
      AND db_id() > 4;
      GO
    }

    noncompliant_keys = sql_session.query(asymmetric_key_size_query).column('key_name')

    if input('excluded_dbs').include? db
      describe "#{db} db: Database excluded from testing." do
        skip "The #{db} database was excluded from testing by choice of the user."
      end
    elsif input('encryption_disabled_dbs').include? db
      describe "#{db} db: Database listed as not requiring encryption." do
        skip "The #{db} database was listed as not requiring encryption. Hence, it was excluded from testing by choice of the user."
      end
    elsif encryption_usage.empty?
      describe "#{db} db: Asymmetric Key Size" do
        it "should be set to 'greater than or equal to 2048'." do
          failure_message = "No asymmetric keys found in this database."
          expect(encryption_usage).not_to be_empty, failure_message
        end
      end
    else
      describe "#{db} db: Asymmetric Key Size" do
        it "should be set to 'greater than or equal to 2048'." do
          failure_message = "List of other key sizes: #{noncompliant_keys.join(", ")}"
          expect(noncompliant_keys).to be_empty, failure_message
        end
      end
    end
  end
end