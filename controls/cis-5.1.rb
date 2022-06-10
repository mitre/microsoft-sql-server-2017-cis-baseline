# encoding: UTF-8

control "microsoft-sql-server-2017-cis-5.1" do
  title "Ensure 'Maximum number of error log files' is set to greater than or equal to '12' (Automated)"
  desc "SQL Server error log files must be protected from loss. The log files must be
backed up 
before they are overwritten. Retaining more error logs helps prevent loss from
frequent 
recycling before backups can occur."
  desc "rationale", "The SQL Server error log contains important information about major server
events and 
login attempt information as well."
  desc "check", "Perform either the GUI or T-SQL method shown: 
1.1.1.7 GUI Method 
 
1. Open SQL Server Management Studio. 
2. Open Object Explorer and connect to the target instance. 
3. Navigate to the Management tab in Object Explorer and expand. Right click on
the 
SQL Server Logs file and select Configure. 
4. Verify the Limit the number of error log files before they are recycled
checkbox 
is checked 
5. Verify the Maximum number of error log files is greater than or equal to 12 
  
 
1.1.1.8 T-SQL Method 
 
Run the following T-SQL. The NumberOfLogFiles returned should be greater than or
equal 
to 12. 
DECLARE @NumErrorLogs int; 
EXEC master.sys.xp_instance_regread 
N'HKEY_LOCAL_MACHINE', 
N'Software\\Microsoft\\MSSQLServer\\MSSQLServer', 
N'NumErrorLogs', 
@NumErrorLogs OUTPUT; 
SELECT ISNULL(@NumErrorLogs, -1) AS [NumberOfLogFiles];"
  desc "fix", "Adjust the number of logs to prevent data loss. The default value of 6 may be
insufficient for 
a production environment. Perform either the GUI or T-SQL method shown: 
1.1.1.9 GUI Method 
 
1. Open SQL Server Management Studio. 
2. Open Object Explorer and connect to the target instance. 
3. Navigate to the Management tab in Object Explorer and expand. Right click on
the 
SQL Server Logs file and select Configure 
4. Check the Limit the number of error log files before they are recycled 
5. Set the Maximum number of error log files to greater than or equal to 12 
1.1.1.10 T-SQL Method 
 
Run the following T-SQL to change the number of error log files, replace
<NumberAbove12> 
with your desired number of error log files: 
EXEC master.sys.xp_instance_regwrite 
N'HKEY_LOCAL_MACHINE', 
N'Software\\Microsoft\\MSSQLServer\\MSSQLServer', 
N'NumErrorLogs', 
REG_DWORD, 
<NumberAbove12>;"
  desc "impact", "Once the max number of error logs is reached, the oldest error log file is
deleted each time 
SQL Server restarts or sp_cycle_errorlog is executed."
  desc "default_value", "6 SQL Server error log files in addition to the current error log file are
retained by default."
  impact 0.5
  ref 'https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/scm-services-configure-sql-server-error-logs'
  tag nist: ['AU-4']
  tag severity: "medium"
  tag cis_controls: [
    { '6' => ['6.3'] },
    { '7' => ['6.4'] }
  ] 
  tag cis_controls: " 
Controls 
Version 
Control 
IG 1 IG 2 IG 3 
v7 
6.4 Ensure adequate storage for logs 
 
Ensure that all systems that store logs have adequate storage space for the logs

generated. 
 
 
 
v6 
6.3 Ensure Audit Logging Systems Are Not Subject To Loss 
 i.e. rotation archive 
 
Ensure that all systems that store logs have adequate storage space for the logs

generated on a regular basis so that log files will not fill up between log
rotation 
intervals. The logs must be archived and digitally signed on a periodic basis."

  sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'))

  error_logs_num_query = %{
    DECLARE @NumErrorLogs AS INT;
    EXEC master.sys.xp_instance_regread
    @rootkey = N'HKEY_LOCAL_MACHINE',
    @key = N'SOFTWARE\\Microsoft\\MSSQLServer\\MSSQLServer',
    @value_name = N'NumErrorLogs',
    @value = @NumErrorLogs OUTPUT;
    SELECT ISNULL(@NumErrorLogs, -1) as error_log_num;
  }

  if sql_session.query(error_logs_num_query).rows[0].keys.include? "error_log_num"
    describe "'Maximum number of error log files' should be set to greater than or equal to '12'. The number" do
      subject { sql_session.query(error_logs_num_query).rows[0]["error_log_num"].to_i }
      it { should be >= input('max_error_logs') }
    end
  else
    unavailable_file = sql_session.query(error_logs_num_query).rows[1].values[0].to_i
    describe "'Maximum number of error log files'" do
      it "should be set to greater than or equal to '12'." do
        failure_message = "Registry value for 'NumErrorLogs' not found."
        expect(unavailable_file).not_to equal(-1), failure_message
      end
    end
  end
end
