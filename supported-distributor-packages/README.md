# Uptycs Distributor Package Sharing Script

Uptycs now provides a managed distributor package in us-east-1 and us-east-2.  This folder 
contains a script `share_uptycs_package.py` which will make an api call to Uptycs to request 
that the packages are shared in the given account.

The folder also includes a template `Uptycs-Managed-Package-State-Manager.yaml` which can be 
applied after the script is run. The template creates a Stackset that can be applied to multiple 
regions 

## Requesting that the Uptycs Package is Shared

Run the `share_uptycs_package.py` script.

This script allows you to share an Uptycs Distributor package to an AWS account in specified regions.

The script requires three inputs:

1. `account_id` - The AWS account ID.
2. `regions_file` - A JSON file containing the regions where the package should be shared.
3. `api_key_file` - A file containing the API keys for Uptycs.

### Dependencies

The script requires the following packages:
- `argparse`
- `datetime`
- `json`
- `logging`
- `os`
- `time`
- `jwt`
- `requests`

If necessary, these can be installed using pip by running 
```pip install -r requirements.txt```

### Usage

First, clone and navigate into the directory:


    
To run the script, use the following command structure:

```
Arguments:

-a, --account_id:       Required. The account ID associated with the operation.
-r, --regions_file:     Required. The path to a JSON file containing an array of regions.
-k, --api_key_file:     Optional. The path to a JSON file containing Uptycs API keys.
-s, --secretsmanager:   Optional. The ARN of the AWS Secrets Manager secret containing Uptycs API keys.
-l, --log:              Optional. Sets the log level. Accepted values are 'debug' and 'info'. Default is 'info'.
```

Example Command:

```python script_name.py -a "123456789012" -r "/path/to/regions.json" -k "/path/to/api_keys.json" -l "debug"```

OR

```python script_name.py -a "123456789012" -r "/path/to/regions.json" -s "arn:aws:secretsmanager:us-west-2:123456789012:secret:mySecret-a1b2c3" -l "info"```

Please ensure that the JSON files for regions and API keys are properly formatted. The regions file should contain a key 'regions' with an array of region strings. The API keys file should include 'domain', 'customerId', 'key', and 'secret' keys.


## Create the State Manager Association

Load the Cloudformation template `Uptycs-Managed-Package-State-Manager.yaml`