# encoding: UTF-8

control "microsoft-sql-server-2017-cis-6.1" do
  title "Ensure Database and Application User Input is Sanitized (Manual)"
  desc "Always validate user input received from a database client or application by
testing type, 
length, format, and range prior to transmitting it to the database server."
  desc "rationale", "Sanitizing user input drastically minimizes risk of SQL injection."
  desc "check", "Check with the application teams to ensure any database interaction is through
the use of 
stored procedures and not dynamic SQL. Revoke any INSERT, UPDATE, or DELETE
privileges 
to users so that modifications to data must be done through stored procedures.
Verify that 
there's no SQL query in the application code produced by string concatenation."
  desc "fix", "The following steps can be taken to remediate SQL injection vulnerabilities: 
- Review TSQL and application code for SQL Injection 
- Only permit minimally privileged accounts to send user input to the server 
- Minimize the risk of SQL injection attack by using parameterized commands and 
stored procedures 
- Reject user input containing binary data, escape sequences, and comment 
characters
- Always validate user input and do not use it directly to build SQL statements"
  desc "impact", "Sanitize user input may require changes to application code or database object
syntax. 
These changes can require applications or databases to be taken temporarily
off-line. Any 
change to TSQL or application code should be thoroughly tested in testing
environment 
before production implementation."
  impact 0.5
  ref 'https://owasp.org/www-community/attacks/SQL_Injection'
  tag nist: ['SI-10']
  tag severity: "medium"
  tag cis_controls: [
    { '6' => ['18.3'] },
    { '7' => ['18.2'] }
  ]
  
  describe "Ensure Database and Application User Input is Sanitized." do
    skip "This control requires a manual review to ensure that Database and Application User Input is Sanitized."
  end
end