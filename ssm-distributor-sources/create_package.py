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


Creates Uptycs distributor package
"""

import argparse
import datetime
import hashlib
import json
import logging
import os
import random
import re
import string
import time
import zipfile
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any

import boto3
import jwt
import requests
import urllib3
from botocore.exceptions import BotoCoreError, ClientError

urllib3.disable_warnings()
S3PREFIX = 'uptycs'
TIMEOUT = 9000
ASSET_GRP_NAME = 'assets'
PATH_TO_BUCKET_FOLDER = '../s3-bucket/'
PACKAGE_NAME = 'UptycsAgent'
INSTALLER_VERSION = '1.0'
OS_LIST = ['windows', 'linux']
MAP_FILE = 'uptycs-agent-mapping.json'
AUTHFILE = 'apikey.json'
PACKAGE_DESCRIPTION = \
    'The Uptycs platform provides you with osquery installation packages for ' \
    'all supported operating systems, configures it for optimal data collection, ' \
    'and automatically schedules the queries necessary to track the historical ' \
    'state and activity of all of your assets. '

import boto3
from botocore.exceptions import ClientError


class CloudFormationManager:
    def __init__(self, region_name='us-east-1'):
        self.client = boto3.client('cloudformation', region_name=region_name)

    def _load_template_body(self, template_path):
        """Load CloudFormation template from a local file.

        Args:
            template_path (str): Path to the local CloudFormation template file.
        Returns:
            str: The content of the CloudFormation template.
        """
        try:
            with open(template_path, 'r') as file:
                return file.read()
        except FileNotFoundError:
            return None

    def create_stack(self, stack_name, template_path=None, template_url=None, parameters=None,
                     capabilities=None):
        """Create a CloudFormation stack using either a local template file or a template URL.

        Args:
            stack_name (str): The name of the stack.
            template_path (str): Optional. Local path to the CloudFormation template file.
            template_url (str): Optional. URL to the CloudFormation template.
            parameters (list): Optional. A list of parameters that specify input parameters for the stack.
            capabilities (list): Optional. A list of capabilities. Example: ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"]
        Returns:
            str: Stack ID if created successfully, else an error message.
        """
        if not template_path and not template_url:
            return "Either template_path or template_url must be provided."
        if template_path and template_url:
            return "Please provide either template_path or template_url, not both."

        try:
            if template_path:
                template_body = self._load_template_body(template_path)
                if template_body is None:
                    return f"Template file at {template_path} not found."
                create_params = {'TemplateBody': template_body}
            else:
                create_params = {'TemplateURL': template_url}

            if parameters is not None:
                create_params['Parameters'] = parameters
            if capabilities is not None:
                create_params['Capabilities'] = capabilities

            response = self.client.create_stack(
                StackName=stack_name,
                **create_params
            )
            return response['StackId']
        except ClientError as e:
            return f"Failed to create stack: {e}"




class SecretsFetcher(ABC):
    @abstractmethod
    def fetch_secrets(self):
        pass


class FileSecretsFetcher(SecretsFetcher):
    def __init__(self, filepath):
        self.filepath = filepath

    def fetch_secrets(self):
        with open(self.filepath, 'r') as file:
            data = json.load(file)
        return data


class SecretsManagerFetcher(SecretsFetcher):
    def __init__(self, secret_identifier, region_name):
        # Initialize the SecretsManagerClient with the provided identifier and region.
        self.secrets_manager_client = SecretsManagerClient(secret_identifier, region_name)

    def fetch_secrets(self):
        # Use the get_secret_value method of SecretsManagerClient to fetch the secret.
        secret_value = self.secrets_manager_client.get_secret_value()
        # Assuming the secret is stored in JSON format, parse it into a Python dictionary. Note:
        # You may need to handle exceptions or errors appropriately depending on your use case.
        try:
            secrets = json.loads(secret_value)
            return secrets
        except json.JSONDecodeError:
            # Handle the case where the secret string is not in valid JSON format. This part
            # depends on how you want to deal with such cases, for example, logging an error or
            # raising an exception.
            print("Failed to parse the secret value as JSON.")
            return None


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
            # Check if secret_identifier is an ARN by looking for "arn:" prefix and sufficient
            # segments
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


class DistributorFilePackager:
    # pylint: disable=R0902
    """
    Class to represent a AWS Distributor package.
    """
    OSQUERY_PACKAGE_NAME_TEMPLATE = '{dir}-{version}.zip'

    def __init__(self, installer_version: str, with_remediation: bool, package_downloads_api):
        """
        Initializes an instance of the DistributorFilePackager class.

        Args:
            installer_version (str): The version of the installer package.
            with_remediation (bool): Whether or not to include the remediation package.
        """
        self.logger = LogHandler(str(self.__class__))
        self.manifest_dict = {}
        self.with_remediation = with_remediation
        self.dirs = set()
        self.zip_file_list = set()
        self.build_configs = self._parse_mappings(MAP_FILE)
        self.dir_list = os.listdir()
        self.installer_version = installer_version
        self.package_downloads_api = package_downloads_api  # Store the instance

        for os_type in OS_LIST:
            for installer in self.build_configs[os_type]:
                self.dirs.add(installer['dir'])
                self.zip_file_list.add(
                    self.OSQUERY_PACKAGE_NAME_TEMPLATE.format(dir=installer["dir"],
                                                              version=self.installer_version))

    def download_osquery_files(self) -> None:
        """Download the osquery files for each operating system type and architecture."""
        for os_type in OS_LIST:
            for installer in self.build_configs[os_type]:
                self._add_binary_to_dir(installer)

    def create_staging_dir(self) -> None:
        """Create a staging directory and zip files from each directory in self.dirs."""
        for _dir in self.dirs:
            self._create_zip_files(_dir)
        self._generate_manifest()

    def add_files_to_bucket(self, bucket_name: str, aws_region: str) -> None:
        """
        Upload the zip files in self.zip_file_list to the specified S3 bucket.

        Args:
            bucket_name (str): The name of the S3 bucket.
            aws_region (str): The name of the AWS region.
        """
        bucket = ManagePackageBucket(aws_region)
        bucket.update(bucket_name, self.zip_file_list)

    def _add_binary_to_dir(self, dir_config: Dict) -> None:
        """
        Download the osquery binary for the specified directory configuration.
        Args:
             dir_config (Dict): A dictionary containing the directory configuration information.
            The dictionary should contain the following keys:
                - dir: The directory to download the osquery binary to.
                - arch_type: The architecture of the OS, e.g. "x64", "arm64", etc.
                - upt_package: The name of the OS, as expected by the UptApi.
        """
        working_dir = dir_config.get('dir')
        upt_arch = dir_config.get('arch_type')
        upt_os_name = dir_config.get('upt_package')
        upt_protection_query_params = {
            'remediationPackage': 'true'
        }
        arm64_query_params = {
            'gravitonPackage': 'true'
        }
        query_params = {
            'osqVersion': self.installer_version
        }
        if upt_arch == 'arm64':
            query_params.update(arm64_query_params)
        if self.with_remediation:
            query_params.update(upt_protection_query_params)

        print(f'Downloading {upt_os_name} for {upt_arch} to folder {working_dir}')
        self.package_downloads_api.package_downloads_osquery_os_asset_group_id_get(
            upt_os_name,
            working_dir,
            query_params
        )

    @staticmethod
    def _parse_mappings(filename: str) -> Dict:
        """
        Parses the specified file and returns the configuration data.

        Args:
            filename (str): The name of the file to parse.

        Returns:
            dict: The configuration data.
        """
        with open(filename, 'rb') as file_handle:
            json_data = json.loads(file_handle.read())
        return json_data

    def _generate_manifest(self) -> None:
        # pylint: disable=R0914:
        """
        Generates the manifest.json file required to create the ssm document.
        """
        # Create an empty dictionary to hold the instance information for each OS type and version.
        manifest_instance_info = {}

        # Initialize the manifest dictionary with the required fields.
        self.manifest_dict = {
            "schemaVersion": "2.0",
            "publisher": "Uptycs.",
            "description": PACKAGE_DESCRIPTION,
            "version": self.installer_version
        }

        # Iterate through each OS type and configuration and add its information to the manifest.
        for os_type in OS_LIST:
            for config in self.build_configs[os_type]:
                name = config['name']
                arch_type = config['arch_type']
                version = config['major_version']
                if not len(config['minor_version']) == 0:
                    version = version + "." + config['minor_version']
                if name in manifest_instance_info:
                    pass
                else:
                    manifest_instance_info[name] = {}

                if version in manifest_instance_info[name]:
                    pass
                else:
                    manifest_instance_info[name][version] = {}

                if arch_type in manifest_instance_info[name][version]:
                    pass
                else:
                    manifest_instance_info[name][version][arch_type] = {}

                zip_file_name = self.OSQUERY_PACKAGE_NAME_TEMPLATE.format(
                    dir=config["dir"],
                    version=self.installer_version)
                manifest_instance_info[name][version][arch_type] = {'file': zip_file_name}

        # Generate a SHA256 digest for each file in the zip file list and add its information to
        # the manifest.
        try:
            hashes = self._generate_digest(self.zip_file_list)
            self.manifest_dict["packages"] = manifest_instance_info
            obj = {}
            for hash_val in hashes:
                for key, val in hash_val.items():
                    obj.update({key: {'checksums': {"sha256": val}}})
            file_list = {"files": obj}
            self.manifest_dict.update(file_list)

            # Write the manifest file to the S3 bucket folder and add it to the zip file list.
            manifest_file_path = PATH_TO_BUCKET_FOLDER + 'manifest.json'
            self._write_manifest_file(manifest_file_path, self.manifest_dict)
            self.zip_file_list.add('manifest.json')

        # Log an error message if there are any exceptions while generating the manifest.
        except (KeyError, ValueError) as err:
            self.logger.error(f'Exception {err}')

    @staticmethod
    def _write_manifest_file(file: str, json_data: Dict) -> None:
        """
        Write the given JSON data to the specified file.

        Args:
            file (str): The file to write the data to.
            json_data (Dict): The JSON data to write.
        """
        try:
            with open(file, 'w', encoding="utf-8") as file_handle:
                file_handle.write(json.dumps(json_data))
                print('Writing manifest file')
        except (FileNotFoundError, FileExistsError, OSError) as err:
            print(err)

    def _create_zip_files(self, directory: str) -> None:
        """
        Creates a zip file from the contents of the specified directory
        and saves it to the specified path.

        Args:
            directory (str): The directory to create a zip file from.
        """
        # Generate the path to the zip file
        zip_path = os.path.join(PATH_TO_BUCKET_FOLDER, f"{directory}-{self.installer_version}.zip")

        # Create any necessary directories for the zip file
        os.makedirs(os.path.dirname(zip_path), exist_ok=True)

        # Create the zip file and write the contents of the directory to it
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, file_list in os.walk(f"{directory}/"):
                for file in file_list:
                    file_path = os.path.join(root, file)
                    zipf.write(file_path, os.path.basename(file_path))

        # Output a message to indicate that the zip file was successfully created
        print(f'Successfully created zip file: {zip_path}')

    @staticmethod
    def _generate_digest(zip_file_list: set) -> List[Dict[str, str]]:
        """
        Generate a SHA-256 digest for each file in the provided list.

        Args:
            zip_file_list (set): A set of file names to generate the digests for.

        Returns:
            List[Dict[str, str]]: A list of dictionaries,
            each containing a file name and its corresponding SHA-256 digest.
        """
        hashes = []
        for filename in zip_file_list:
            file_path = os.path.join(PATH_TO_BUCKET_FOLDER, filename)
            with open(file_path, 'rb') as file_handle:
                read_bytes = file_handle.read()  # read entire file as bytes
                readable_hash = hashlib.sha256(read_bytes).hexdigest()
                hashes.append({filename: readable_hash})

        return hashes


class LogHandler:
    """Class for handling logging to file and console"""

    def __init__(self, logger_name):
        """
        Initializes a new LogHandler object.

        Args:
            logger_name (str): The name of the logger.

        Attributes:
            logger (logging.Logger): The logger instance.
        """
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.DEBUG)
        log_format = '%(asctime)s: %(levelname)s: %(name)s: %(message)s'
        filename = os.path.splitext(os.path.basename(__file__))[0] + '.log'
        file_handler = logging.FileHandler(filename)
        console_handler = logging.StreamHandler()
        formatter = logging.Formatter(log_format)
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def debug(self, msg):
        """
        Log a debug message.

        Args:
            msg (str): The debug message
        """
        self.logger.debug(msg)

    def info(self, msg):
        """
        Log an info message.

        Args:
            msg (str): The info message
        """
        self.logger.info(msg)

    def warning(self, msg):
        """
        Log a warning message.

        Args:
            msg (str): The warning message
        """
        self.logger.warning(msg)

    def error(self, msg):
        """
        Log an error message.

        Args:
            msg (str): The error message
        """
        self.logger.error(msg)

    def critical(self, msg):
        """
        Log a critical message.

        Args:
            msg (str): The critical message
        """
        self.logger.critical(msg)


class UptApiAuthError(Exception):
    """Base class for exceptions raised by UptApiAuth."""


class ApiConfigFileNotFoundError(UptApiAuthError):
    """Exception raised when an API config file is not found."""


class InvalidApiConfigFileError(UptApiAuthError):
    """Exception raised when an API config file is invalid."""


class InvalidApiAuthParametersError(UptApiAuthError):
    """Exception raised when one or more API authentication parameters are missing or invalid."""


class AuthManager:
    """Handles authentication to the API and returns a valid authentication header."""

    def __init__(self, secrets_fetcher, logger=None):
        """
        Initializes the AuthManager with secrets fetched from the provided SecretsFetcher.

        Args:
            secrets_fetcher: An instance of a class implementing the SecretsFetcher interface.
            logger: Optional logger instance for logging messages.
        """
        self.logger = logger
        secrets = secrets_fetcher.fetch_secrets()

        self.validate_secrets(secrets)

        self.base_url = f'https://{secrets["domain"]}{secrets.get("domainSuffix", "")}/public/api/customers/{secrets["customerId"]}'
        self.header = self._generate_auth_header(secrets)

    def validate_secrets(self, secrets: Dict[str, Any]):
        """Validates that all required secrets are present."""
        required_keys = ['key', 'secret', 'domain', 'customerId']
        missing_keys = [k for k in required_keys if k not in secrets]
        if missing_keys:
            error_message = f"Missing required secrets: {', '.join(missing_keys)}"
            if self.logger:
                self.logger.error(error_message)
            raise ValueError(error_message)

    def _generate_auth_header(self, secrets: Dict[str, Any]) -> Dict[str, str]:
        """
        Generates an authentication header.

        Args:
            secrets: A dictionary containing the necessary secrets.

        Returns:
            A dictionary with the 'Authorization' header.
        """
        try:
            exp_time = time.time() + 3600  # Token expires in 1 hour
            token = jwt.encode({'iss': secrets['key'], 'exp': exp_time}, secrets['secret'],
                               algorithm="HS256")
            authorization = f'Bearer {token}'
            return {
                'Authorization': authorization,
                'Date': datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"),
                'Content-Type': "application/json"
            }
        except jwt.PyJWTError as error:
            if self.logger:
                self.logger.error("Error encoding JWT: " + str(error))
            raise


class UptApiAuth:
    """Handles authentication to Uptycs and returns a valid authentication token"""

    def __init__(self, secrets_fetcher, logger=None):
        self.logger = logger
        secrets = secrets_fetcher.fetch_secrets()

        key = secrets.get('key')
        secret = secrets.get('secret')
        domain = secrets.get('domain')
        customer_id = secrets.get('customerId')
        domain_suffix = secrets.get('domainSuffix', '')
        if not all([key, secret, domain, customer_id, domain_suffix]):
            if self.logger:
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
            auth_var: str = jwt.encode({'iss': key, 'exp': exp_time}, secret, algorithm="HS256")
            authorization: str = f'Bearer {auth_var}'
        except jwt.exceptions.PyJWTError as error:
            if self.logger:
                self.logger.log_message('error', "Error encoding key and secret with jwt module")
            raise jwt.PyJWTError("Error encoding key and secret with jwt module") from error

        self.header = {
            'authorization': authorization,
            'date': datetime.datetime.utcnow().strftime(
                "%a, %d %b %Y %H:%M:%S GMT"),
            'Content-type': "application/json"}


class ApiClient:
    def __init__(self, auth_manager):
        """
        Initialize the API client with an authentication manager.

        Args:
            auth_manager (AuthManager): The authentication manager that provides the header for authenticated API calls.
        """
        self.auth_manager = auth_manager

    def make_api_call(self, api_endpoint, method, payload=None, **kwargs):
        """
        Make an API call to the specified endpoint using the specified HTTP method.

        Args:
            api_endpoint (str): The endpoint of the API to call.
            method (str): The HTTP method to use (e.g., 'GET', 'POST', 'PUT', 'DELETE').
            payload (dict, optional): The payload to send with the request, if any.
            **kwargs: Additional keyword arguments to pass to the requests method.

        Returns:
            A requests.Response object containing the response from the API call.
        """
        # Construct the full URL for the API call.
        full_url = f"{self.auth_manager.base_url}{api_endpoint}"

        # Get the authentication header from the auth manager.
        headers = self.auth_manager.header

        # Add any additional headers passed in through kwargs.
        headers.update(kwargs.pop('headers', {}))

        # Select the appropriate requests function based on the method.
        http_method_function = getattr(requests, method.lower(), None)
        if http_method_function is None:
            raise ValueError(f"Unsupported HTTP method: {method}")

        # Make the API call.
        response = http_method_function(full_url, headers=headers, json=payload, **kwargs)

        return response


# class UptApiCall:
#     def __init__(self, api_auth, api_endpoint, method, payload: Optional[Dict[str, Any]] = None,
#                  **kwargs):
#         """
#         Initializes an API call with the specified parameters.
#
#         Args:
#             api_auth (UptApiAuth): An instance of UptApiAuth for authentication.
#             api_endpoint (str): The endpoint of the API to be called.
#             method (str): The HTTP method to be used for the API call ('GET', 'POST', 'PUT', 'DELETE').
#             payload (Optional[Dict[str, Any]]): The payload to be sent with the API call (for 'POST' and 'PUT' methods).
#             **kwargs: Additional keyword arguments to be passed to the requests method.
#         """
#         self.api_auth = api_auth
#         self.logger = LogHandler(str(self.__class__))
#         self.base_url = self.api_auth.base_url
#         self.method = method.upper()
#         self.api_endpoint = api_endpoint
#         self.payload = payload
#         self.kwargs = kwargs
#         self.response_json = None
#         self.response_stream = None
#
#         self._make_api_call()
#
#     def _make_api_call(self):
#         """
#         Makes the API call using the requests library and the provided parameters.
#         """
#         # Prepare the URL and headers
#         full_url = f"{self.base_url}{self.api_endpoint}"
#         headers = self.api_auth.header
#
#         # Choose the method and make the call
#         try:
#             if self.method in ['GET', 'POST', 'PUT', 'DELETE']:
#                 request_method = getattr(requests, self.method.lower())
#             else:
#                 raise ValueError("Unsupported HTTP method")
#
#             if self.method in ['POST', 'PUT']:
#                 payload_json = json.dumps(self.payload) if self.payload else None
#                 response = request_method(full_url, headers=headers, data=payload_json,
#                                           verify=False, timeout=TIMEOUT, **self.kwargs)
#             else:
#                 response = request_method(full_url, headers=headers, verify=False, timeout=TIMEOUT,
#                                           **self.kwargs)
#
#             # Process the response
#             if response.status_code == 200:
#                 self.logger.debug(f"Success with {self.method} on {self.api_endpoint}")
#                 if 'application/json' in response.headers.get('Content-Type', ''):
#                     self.response_json = response.json()
#                 else:
#                     self.response_stream = response
#             else:
#                 self.logger.error(
#                     f"Error during {self.method} on {self.api_endpoint}: {response.status_code}")
#                 self.logger.error(response.text)
#
#         except Exception as e:
#             self.logger.error(f"Exception during {self.method} on {self.api_endpoint}: {str(e)}")
#             raise e
#
#     def get_response_json(self) -> Optional[Dict[str, Any]]:
#         """
#         Returns the JSON response of the API call if available.
#
#         Returns:
#             Optional[Dict[str, Any]]: The JSON response of the API call.
#         """
#         return self.response_json
#
#     def get_response_stream(self) -> Optional[Any]:
#         """
#         Returns the raw response stream of the API call if available.
#
#         Returns:
#             Optional[Any]: The raw response stream of the API call.
#         """
#         return self.response_stream
#

class ObjectGroupsApi:
    """
    Class for interacting with Object Groups API endpoints.
    """

    def __init__(self, api_client):
        """
        Initializes the ObjectGroupsApi instance with an ApiClient.

        Args:
            api_client (ApiClient): An instance of ApiClient for making API calls.
        """
        self.api_client = api_client
        self.logger = LogHandler(
            str(self.__class__))  # Ensure LogHandler is properly defined or use standard logging.

    def object_groups_get(self):
        """
        Get the list of object groups.

        Returns:
            The JSON response from the API call.
        """
        api_endpoint = '/objectGroups'
        try:
            response = self.api_client.make_api_call(api_endpoint, 'GET')
            return json.loads(response.content)  # Assuming ApiClient provides this
            # method to get the JSON response.
        except Exception as error:
            self.logger.error(f"Error fetching object groups: {str(error)}")
            raise  # It's generally a good practice to raise exceptions for the caller to handle unless you have a specific reason to suppress them.

    def object_groups_object_group_id_delete(self, object_group_id):
        """
        Delete an object group by its ID.

        Args:
            object_group_id (str): The ID of the object group to delete.

        Returns:
            The JSON response from the API call.
        """
        api_endpoint = f'/objectGroups/{object_group_id}'
        try:
            response = self.api_client.make_api_call(api_endpoint, 'DELETE')
            return response.get_response_json()  # Assuming ApiClient provides this method to get the JSON response.
        except Exception as error:
            self.logger.error(f"Error deleting object group {object_group_id}: {str(error)}")
            raise  # As above, consider raising exceptions for upstream handling.


class PackageDownloadsApi:
    # Initialization and _get_asset_group_id remain unchanged

    def __init__(self, api_client, logger, asset_group_id=None):
        """
        Initializes an instance of PackageDownloadsApi.

        Args:
            api_client: An instance of ApiClient for making API calls.
            logger: An instance of a logging class to log messages.
            asset_group_id (Optional[str]): The ID of the asset group. If not provided, it will be fetched dynamically.
        """
        self.api_client = api_client
        self.logger = logger
        self.asset_group_id = asset_group_id or self._get_asset_group_id()

    def _get_asset_group_id(self) -> str:
        """
        Retrieves the asset group ID from the API. Implement this method based on your API's way of fetching asset groups.

        Returns:
            str: The asset group ID.
        """
        # Example implementation - adjust according to your actual API:
        obj_grp_list = ObjectGroupsApi(self.api_client).object_groups_get().get('items')
        for obj_grp in obj_grp_list:
            if obj_grp.get('name') == ASSET_GRP_NAME:
                return obj_grp.get('id')
        return None

    def osquery_packages_get_version(self):
        """
        Retrieves the version number of the current osquery packages.
        """
        api_endpoint = '/osqueryPackages'
        response = self.api_client.make_api_call(api_endpoint, 'GET')
        if response.ok:
            data = response.json()  # Extract JSON data
            return data['items'][0]['version'].split('-')[0]
        else:
            # Handle error or raise an exception
            self.logger.error(f"Failed to fetch osquery package version: {response.text}")
            response.raise_for_status()

    def package_downloads_osquery_os_asset_group_id_get(self, os_name: str, dir_name: str,
                                                        query_params: Optional[
                                                            Dict[str, str]] = None):
        """
        Downloads an osquery package for the given OS and asset group ID and saves it to the specified directory.
        """
        api_endpoint = f'/packageDownloads/osquery/{os_name}/{self.asset_group_id}'
        if query_params:
            # Properly encode query parameters
            api_endpoint += '?' + '&'.join(
                [f'{key}={value}' for key, value in query_params.items()])

        response = self.api_client.make_api_call(api_endpoint, 'GET', stream=True)

        if response.ok:
            content_disp = response.headers.get('Content-Disposition', '')
            file_name = re.findall('filename="([^"]+)"', content_disp)[0]
            save_path = os.path.join(dir_name, file_name)
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            with open(save_path, 'wb') as file:
                for chunk in response.iter_content(chunk_size=1024):
                    file.write(chunk)
            print(f"Package downloaded and saved to {save_path}")
        else:
            # Handle error or raise an exception
            self.logger.error(f"Failed to download the package: {response.text}")
            response.raise_for_status()


class ManagePackageBucket:
    # pylint: disable=R0903
    """
    Class to handle all interactions with the S3 Bucket used for the distributor package
    """

    def __init__(self, region_name: str) -> None:
        """
        Initializes an instance of the ManagePackageBucket class.

        Args:
            region_name (str): The name of the AWS region.
        """
        self.logger = LogHandler(str(self.__class__))
        self.region = region_name
        self.s3_client = boto3.client('s3', region_name=self.region)

    def update(self, bucket_name: str, file_list: set) -> bool:
        """
        Updates the bucket contents.

        Args:
            bucket_name (str): The name of the S3 bucket.
            file_list (list[str]): A list of file names to be uploaded.

        Returns:
            bool: True if the update was successful, else False.
        """
        if not self._bucket_exists(bucket_name):
            self._create_bucket(bucket_name)
        for file in file_list:
            file_path = os.path.join(PATH_TO_BUCKET_FOLDER, file)
            object_key = f"{S3PREFIX}/{file}"
            self._upload_file(file_path, bucket_name, object_key)
        return True

    def _bucket_exists(self, bucket_name: str) -> bool:
        """
        Checks that the S3 bucket exists in the region.

        Args:
            bucket_name (str): The name of the S3 bucket.

        Returns:
            bool: True if the bucket exists, else False.
        """
        try:
            response = self.s3_client.list_buckets()
            for bucket in response['Buckets']:
                if bucket_name == bucket["Name"]:
                    print('Bucket already exists -Skipping Creation:')
                    return True
            return False
        except ClientError as err:
            self.logger.error(f'Error listing buckets {err}')
            return False

    def _create_bucket(self, bucket_name: str) -> bool:
        """
        Creates an S3 bucket.

        Args:
            bucket_name (str): The name of the bucket to create.

        Returns:
            bool: True if the bucket was created, else False.
        """
        print(f'Creating bucket: {bucket_name}')
        try:
            if self.region == 'us-east-1':
                self.s3_client.create_bucket(Bucket=bucket_name)
            else:
                location = {
                    'LocationConstraint': self.region} if self.region != 'us-east-1' else None
                self.s3_client.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration=location
                )
            return True
        except ClientError as err:
            self.logger.error(f'Error creating bucket {err}')
            return False

    def _upload_file(self, file_path: str, bucket_name: str, object_key: str) -> bool:
        """Upload a file to an S3 bucket

        :param file_path: File to upload
        :param bucket_name: Bucket to upload to
        :param object_key: S3 object key
        :return: True if file was uploaded, else False
        """
        try:
            start_time = time.time()
            print(f'Uploading file {file_path}:')
            with open(file_path, "rb") as content:
                self.s3_client.put_object(
                    Bucket=bucket_name,
                    Key=object_key,
                    Body=content
                )
            time_taken = time.time() - start_time
            print(f"Successfully finished uploading files to s3 bucket. in {time_taken}s")
            return True
        except (BotoCoreError, ClientError) as err:
            self.logger.error(f'Upload error {err}')
            return False


def setup_secrets_fetcher(args):
    if args.config:
        return FileSecretsFetcher(args.config)
    elif args.secretsmanager:
        return SecretsManagerFetcher(args.secretsmanager, args.aws_region)
    raise ValueError("Either a config file or Secrets Manager ARN must be provided.")


# def setup_distributor_file_packager(version, upt_protection, download_files, secrets_fetcher):
#     api_auth = AuthManager(secrets_fetcher)
#     api_client = ApiClient(api_auth)
#
#     package_downloads_api = PackageDownloadsApi(
#         api_client)  # Assuming constructor accepts an ApiClient instance
#     uptycs_packager = DistributorFilePackager(version, upt_protection, package_downloads_api,
#                                               download_files)
#
#     return uptycs_packager

def create_secrets_fetcher(args):
    if args.config:
        return FileSecretsFetcher(args.config)
    elif args.secretsmanager:
        return SecretsManagerFetcher(args.secretsmanager, args.aws_region)
    else:
        raise ValueError("A configuration for secrets fetching must be provided.")


def create_auth_manager(secrets_fetcher):
    return AuthManager(secrets_fetcher)


def create_api_client(auth_manager):
    return ApiClient(auth_manager)


def create_object_groups_api(api_client):
    return ObjectGroupsApi(api_client)


def main():
    """

    Main function

    """
    # pylint: disable=W0603
    global AUTHFILE
    parser = argparse.ArgumentParser(
        description='Create and upload Distributor packages to the AWS SSM'
    )
    parser.add_argument('-c', '--config', required=False,
                        help='REQUIRED: The path to your auth config file downloaded from Uptycs '
                             'console')
    parser.add_argument('-s', '--secretsmanager', type=str, required=False,
                        help='The Secrets Manager ARN containing Uptycs API keys')
    parser.add_argument('-b', '--s3bucket', default=None,
                        help='OPTIONAL: Name of the S3 bucket used to stage the zip files. '
                             'If not set the bucket will have the name format '
                             'uptycs-dist- + random_string')
    parser.add_argument('-p', '--package_name', default='UptycsAgent',
                        help='OPTIONAL: Use with -d to specify the name of the Distributor '
                             'Package that you will create using files .rpm and .deb files that '
                             'you have added manually')
    parser.add_argument('-r', '--aws_region', default='us-east-1',
                        help='OPTIONAL: The AWS Region that the Bucket will be created in')
    parser.add_argument('-v', '--package_version', default=None,
                        help='OPTIONAL: Use with -d to specify set the Osquery Version if you have '
                             'added the files manually in the format eg 5.7.0.23')
    parser.add_argument('-d', '--download', action='store_false',
                        default=True,
                        help='OPTIONAL: DISABLE the download install files via API. Use if you are '
                             'adding the .rpm and .deb files to the directories manually')

    parser.add_argument('-o', '--sensor_only', dest='sensor_only', action='store_true',
                        default=False,
                        help='OPTIONAL: Setup package without Uptycs protect.  By default the '
                             'Uptycs Protect agent will be used')
    logging.basicConfig(level=logging.INFO)  # Adjust the logging level as needed
    logger = logging.getLogger(__name__)
    args = parser.parse_args()

    if args.download is False and (args.package_version is None or args.package_name is None):
        parser.error('-v/--package_version and -p/--package_name are mandatory with -d/--download '
                     'flag')

    region = args.aws_region
    package_version: Optional[Any] = args.package_version

    try:
        secrets_fetcher = create_secrets_fetcher(args)
        auth_manager = create_auth_manager(secrets_fetcher)
        api_client = create_api_client(auth_manager)
    except Exception as e:
        print(e)
    download_files = args.download

    if args.sensor_only:
        upt_protection = False
    else:
        upt_protection = True

    s3_bucket = args.s3bucket if args.s3bucket else 'uptycs-dist-' + ''.join(
        random.sample(string.ascii_lowercase, 6))

    package_download = PackageDownloadsApi(api_client, logger)
    if package_version:
        #
        # Get the osquery version available via the Uptycs API
        #
        version = args.package_version
    else:
        version = package_download.osquery_packages_get_version()
    #
    # Initialise the Distributor package object for this version
    #
    uptycs_packager = DistributorFilePackager(version, upt_protection, package_download)
    #
    # (Optional) Download the osquery binaries from the Uptycs API
    # You can add older versions of the files manually.
    if download_files:
        uptycs_packager.download_osquery_files()
    #
    # Generate the zip file and manifest and add them to the local staging folder
    #
    uptycs_packager.create_staging_dir()
    uptycs_packager.add_files_to_bucket(s3_bucket, region)


    cf_manager = CloudFormationManager(region_name=region)
    cf_manager.create_stack('Uptycs-State-Manager-Self',
                            template_path='../cloudformation/Uptycs-State-Manager.yaml',
                            parameters=[{'ParameterKey': 'UptycsSsmPackageBucket',
                                        'ParameterValue': s3_bucket}],
                            Capabilities=[
                                'CAPABILITY_IAM' | 'CAPABILITY_NAMED_IAM'],
                            )



if __name__ == '__main__':
    main()
