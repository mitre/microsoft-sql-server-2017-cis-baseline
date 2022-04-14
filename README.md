# microsoft-sql-server-2017-cis-baseline
An InSpec Profile to validate the secure configuration of Microsoft SQL Server 2017, against [CIS](https://www.cisecurity.org/cis-benchmarks/)'s Benchmark for Microsoft SQL Server 2017 version 1.2.0.

## Getting Started  

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

Latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

## Tailoring to Your Environment
The following inputs must be configured in an inputs ".yml" file for the profile to run correctly for your specific environment. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

```yaml
# Username MSSQL DB Server
user: ''

# Password MSSQL DB Server
password: ''

# Hostname of MSSQL DB Server
host: ''

# Instance name of MSSQL DB Server
instance: ''

# Port for MSSQL DB Server (numeric)
port: 

# Approved version expected to be installed (numeric)
approved_sql_version: 

# Set to True if the MS SQL Server instance is clustered
clustered_instance: False

# Enter the maximum number of error log files allowed (CIS required value is 12; this value is not hard-coded to allow for tailoring this profile to organizational requirements)
max_error_logs: 12

# List of the databases excluded from being evaluated
excluded_dbs: []

# List of the databases that are not required to be encrypted
encryption_disabled_dbs: []
```

# Running This Baseline Directly from Github

```
# How to run
inspec exec https://github.com/mitre/microsoft-sql-server-2017-cis-baseline/archive/master.tar.gz -t winrm://<hostip> --user=<admin-account> --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

### Different Run Options

  [Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Running This Baseline from a local Archive copy 

If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this baseline and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.)

When the __"runner"__ host uses this profile baseline for the first time, follow these steps: 

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/microsoft-sql-server-2017-cis-baseline
inspec archive microsoft-sql-server-2017-cis-baseline
inspec exec <name of generated archive> -t winrm://<hostip> --user=<admin-account> --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter cli json:<path_to_your_output_file/name_of_your_output_file.json>
```
For every successive run, follow these steps to always have the latest version of this baseline:

```
cd microsoft-sql-server-2017-cis-baseline
git pull
cd ..
inspec archive microsoft-sql-server-2017-cis-baseline --overwrite
inspec exec <name of generated archive> -t winrm://<hostip> --user=<admin-account> --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

## Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors
* Shivani Karikar - [karikarshivani](https://github.com/karikarshivani)

## Special Thanks
* Eugene Aronne - [ejaronne](https://github.com/ejaronne)
* Will Dower - [wdower](https://github.com/wdower)

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/mitre/oracle-mysql-ee-5.7-cis-baseline/issues/new).

### NOTICE

© 2018-2020 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE
MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation. 

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.  

### NOTICE

CIS Benchmarks are published by the Center for Internet Security (CIS), see: https://www.cisecurity.org/