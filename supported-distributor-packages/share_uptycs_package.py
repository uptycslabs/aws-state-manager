"""
MIT License

Copyright (c) 2022 Uptycs

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


This script enables Uptycs supported distributor packages to be shared with your AWS account
The package will be shared from an Uptycs account and appear in your "Shared With Me" folder

Usage

share_uptycs_package.py []
"""

import argparse
import datetime
import json
import logging
import os
import time
import jwt
import requests
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from typing import Dict, List, Optional

# pylint: disable=R0903
class LogHandler:
    """A class to encapsulate logging setup and methods for serialization."""

    def __init__(self, logger_name):
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.DEBUG)  # sets the threshold for this logger to level.

        # File handler for the log messages
        file_handler = logging.FileHandler(os.path.join(os.getcwd(), 'my_log.log'))
        file_handler.setLevel(logging.DEBUG)  # sets the threshold for this handler to level.
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def log_message(self, level, message):
        """Log a message with the specified logging level."""
        if level.lower() == 'debug':
            self.logger.debug(message)
        elif level.lower() == 'info':
            self.logger.info(message)
        elif level.lower() == 'warning':
            self.logger.warning(message)
        elif level.lower() == 'error':
            self.logger.error(message)
        elif level.lower() == 'critical':
            self.logger.critical(message)



class SecretsManagerClient:

    """
    Client wrapper for AWS Secrets Manager operations.

    This client simplifies common operations like creating/updating, deleting,
    and retrieving secrets from AWS Secrets Manager.
    """

    def __init__(self, secret_identifier: str, region: str = None) -> None:
        self.logger = LogHandler('SecretsManagerClient').logger
        """
        Initialize the SecretsManagerClient.

        Args:
            secret_identifier (str): The ARN or name of the secret.
            region (str, optional): The AWS region where the secret is located. This is required if secret_identifier is not an ARN.
        """

        try:
            # Check if secret_identifier is an ARN by looking for "arn:" prefix and sufficient segments
            if secret_identifier.startswith("arn:") and len(
                    secret_identifier.split(':')) >= 5:
                # It's an ARN, extract region and secret name from ARN
                arn_parts = secret_identifier.split(':')
                region = arn_parts[3]  # Extract the region from ARN
                secret_name_with_suffix = arn_parts[-1]
                secret_name_parts = secret_name_with_suffix.split('-')[
                                    :-1]  # Exclude the random suffix part
                secret_name = '-'.join(secret_name_parts)  # Extract the secret name from ARN
                self.secret_identifier = secret_name  # Use the extracted secret name
            else:
                # Not an ARN, use the provided secret name and region
                if region is None:
                    raise ValueError(
                        "Region must be provided if secret_identifier is not an ARN.")
                self.secret_identifier = secret_identifier

            # Create the Secrets Manager client with the determined or provided region
            self.secrets_client = boto3.client('secretsmanager', region_name=region)

        except ValueError as e:
            print(f"Value Error: {e}")
        except (BotoCoreError, ClientError) as e:
            print(f"Error initializing Secrets Manager client: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def create_or_update_secret(self, secret_value: str) -> Dict[str, str]:
        """
        Create or update a secret in AWS Secrets Manager.

        Args:
            secret_value (str): The secret value to store.

        Returns:
            dict: The response from the create or update operation.
        """
        try:
            response = self.secrets_client.create_secret(
                Name=self.secret_identifier,
                SecretString=secret_value
            )
        except self.secrets_client.exceptions.ResourceExistsException:
            response = self.secrets_client.update_secret(
                SecretId=self.secret_name,
                SecretString=secret_value
            )

        return response

    def delete_secret(self) -> Dict[str, str]:
        """
        Delete a secret from AWS Secrets Manager.

        Returns:
            dict: The response from the delete operation.
        """
        response = self.secrets_client.delete_secret(
            SecretId=self.secret_identifier,
            ForceDeleteWithoutRecovery=True
        )
        return response

    def get_secret_value(self) -> str:
        """
        Retrieve the value of the secret.

        Returns:
            str: The value of the secret.
        """
        try:
            response = self.secrets_client.get_secret_value(SecretId=self.secret_identifier)
            secret_value = response['SecretString']
            return secret_value
        except Exception as error:
            error_message = json.dumps({'error': f'Error retrieving secret: {str(error)}'})
            print(error_message)
            return error_message  # Return an empty string or error message in JSON format

    def get_secret_arn(self) -> str:
        """
        Retrieve the ARN of the secret.

        Returns:
            str: The ARN of the secret.
        """
        if "arn:" in self.secret_identifier:
            # The identifier is already an ARN
            return self.secret_identifier

        # Else, fetch the ARN using the secret name
        response = self.secrets_client.describe_secret(
            SecretId=self.secret_identifier
        )
        return response['ARN']

class UptApiAuth:
    """Handles authentication to Uptycs and returns a valid authentication token"""

    # pylint: disable=R0913
    def __init__(self, api_config_file=None, key=None, secret=None, domain=None,
                 customer_id=None, domain_suffix='', silent=True, logger=None):
        self.base_url = None
        self.header = None
        self.logger = logger

        if api_config_file is not None:
            try:
                if not silent:
                    self.logger.log_message(
                        'info',
                        f'Reading Uptycs API connection & authorization details from '
                        f'{api_config_file}')
                with open(api_config_file,'r', encoding='utf-8') as file_handle:
                    data = json.load(file_handle)
                key = data.get('key', key)
                secret = data.get('secret', secret)
                domain = data.get('domain', domain)
                customer_id = data.get('customerId', customer_id)
                domain_suffix = data.get('domainSuffix', domain_suffix)
            except FileNotFoundError as error:
                self.logger.log_message('error', f"API config file not found: {error.filename}")
                raise FileNotFoundError(f"API config file not found: {error.filename}") from error
            except (json.JSONDecodeError, KeyError) as error:
                self.logger.log_message('error', f"Invalid API config file: {api_config_file}")
                raise ValueError(f"Invalid API config file: {api_config_file}") from error

        if not all([key, secret, domain, customer_id, domain_suffix]):
            self.logger.log_message('error',
                                    "Please provide either an API key file or all "
                                    "parameters: key, secret, domain, customerId, "
                                    "domainSuffix")
            raise ValueError(
                "Please provide either an API key file or all parameters: "
                "key, secret, domain, customerId, domainSuffix")

        self.base_url = f'https://{domain}{domain_suffix}/public/api/customers/{customer_id}'
        try:
            exp_time = time.time() + 60
            auth_var: str = jwt.encode({'iss': key, 'exp': exp_time}, secret)
            authorization: str = f'Bearer {auth_var}'
        except jwt.exceptions.PyJWTError as error:
            self.logger.log_message('error', "Error encoding key and secret with jwt module")
            raise jwt.PyJWTError("Error encoding key and secret with jwt module") from error

        self.header = {
            'authorization': authorization,
            'date': datetime.datetime.utcnow().strftime(
                "%a, %d %b %Y %H:%M:%S GMT"),
            'Content-type': "application/json"}


def main():
    """
Usage Instructions:

This script is designed to parse an account ID and regions from input and handle API keys either from a file or AWS Secrets Manager. It then performs an operation against a specified endpoint using these parameters.

To run the script, use the following command structure:

python script_name.py -a ACCOUNT_ID -r REGIONS_FILE [-k API_KEY_FILE] [-s SECRETS_MANAGER_ARN] [-l LOG_LEVEL]

Arguments:

-a, --account_id:       Required. The account ID associated with the operation.
-r, --regions_file:     Required. The path to a JSON file containing an array of regions.
-k, --api_key_file:     Optional. The path to a JSON file containing Uptycs API keys.
-s, --secretsmanager:   Optional. The ARN of the AWS Secrets Manager secret containing Uptycs API keys.
-l, --log:              Optional. Sets the log level. Accepted values are 'debug' and 'info'. Default is 'info'.

Example Command:

python script_name.py -a "123456789012" -r "/path/to/regions.json" -k "/path/to/api_keys.json" -l "debug"

OR

python script_name.py -a "123456789012" -r "/path/to/regions.json" -s "arn:aws:secretsmanager:us-west-2:123456789012:secret:mySecret-a1b2c3" -l "info"

Please ensure that the JSON files for regions and API keys are properly formatted. The regions file should contain a key 'regions' with an array of region strings. The API keys file should include 'domain', 'customerId', 'key', and 'secret' keys.

"""

    logger = LogHandler('auth_logger')
    parser = argparse.ArgumentParser(description='Parse account_id and regions from input')

    parser.add_argument('-a', '--account_id', type=str, required=True, help='The Account ID')
    parser.add_argument('-r', '--regions_file', type=str, required=True,
                        help='The JSON file containing regions')
    parser.add_argument('-k', '--api_key_file', type=str, required=False,
                        help='The JSON file containing Uptycs API keys')
    parser.add_argument('-s', '--secretsmanager', type=str, required=False,
                        help='The Secrets Manager ARN containing Uptycs API keys')
    parser.add_argument('-l', '--log', default='info', type=str, choices=['debug', 'info'],
                        help='Set the log level (default: info)')

    args = parser.parse_args()
    level = logging.DEBUG if args.log == 'debug' else logging.INFO
    logger.logger.setLevel(level)

    # Get account_id from arguments
    account_id = args.account_id

    # Read regions from JSON file
    with open(args.regions_file, "r", encoding='utf8') as read_file:
        data = json.load(read_file)
    regions = ",".join(data['regions'])

    # Handle API keys: either from a file or from Secrets Manager
    if args.api_key_file:
        # Read API keys from JSON file
        with open(args.api_key_file, "r", encoding='utf8') as key_file:
            api_keys = json.load(key_file)
        auth_token = UptApiAuth(args.api_key_file, logger=logger)
    elif args.secretsmanager:
        # Access API keys from Secrets Manager
        secrets_client = SecretsManagerClient(args.secretsmanager)
        api_keys = json.loads(secrets_client.get_secret_value())
        auth_token = UptApiAuth(key=api_keys.get('key'), customer_id=api_keys.get(
            'customerId'), secret=api_keys.get('secret'),
            domain_suffix=api_keys.get('domainSuffix'), domain=api_keys.get('domain'),
            logger=logger)
    else:
        logger.error("Either an API key file or a Secrets Manager ARN must be provided.")
        exit(1)


    params = {"regions": regions}
    url = f'{auth_token.base_url}/packagedownloads/osqueryssm/terraform/{account_id}'
    response = requests.get(url, headers=auth_token.header, params=params,timeout=10)

    if response.status_code == 200:
        logger.log_message('critical', f"Success! Server responded with: {response.status_code}")
        print("Successfully shared packages")
    else:
        logger.log_message('critical', f"Failure! Server responded with: {response.status_code}")
        print("Failed to share packages")


if __name__ == '__main__':
    main()
