# AWS Config Compliance Lambda

This AWS Lambda function assesses compliance of AWS resources based on configuration changes and notifications from AWS Config. The function is designed to evaluate and report compliance for S3 buckets and their policies, considering organizational, OU, and database ARN constraints.

## Prerequisites

- AWS account with AWS Config and AWS Lambda set up.
- AWS CLI installed and configured with necessary permissions.
- Python 3.x installed.
- AWS SAM CLI installed (for deployment using AWS SAM).

## Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/samh1029/S3-Config-Check.git
   cd S3-Config-Check
   ```
2. Deploy using AWS SAM:

  ```bash
  sam build
  sam deploy --guided
  ```
  Follow the prompts to configure your deployment. This will package and deploy the Lambda function using AWS SAM, creating the necessary AWS resources.

## Configuration

Environment variables are defined in the CloudFormation template (template.yaml). Modify the Environment section under the Lambda function resource in the template to set the desired values for the following variables:

- ORG_ID: AWS Organization ID (optional).
- OU_ID: Organizational Unit ID (optional).
- USE_DB: Use Database ARN for compliance checks (optional).

## Usage

  Ensure that AWS Config is properly set up to record relevant resource changes.

  When configuration changes occur, AWS Config will trigger the Lambda function.

  The Lambda function evaluates the compliance based on the specified rules and reports the results back to AWS Config.


## Todo

- [ ] inORG
- [ ] inOU
- [ ] inDB

## Functionality

- get_aws_account_id: Retrieves the AWS account ID.
- is_oversized_changed_notification: Checks if the message type is 'OversizedConfigurationItemChangeNotification'.
- get_configuration: Retrieves the configuration item using the getResourceConfigHistory API.
- convert_api_configuration: Converts configuration from the API model to the original invocation model.
- get_configuration_item: Gets the configuration item based on the invoking event.
- is_applicable: Checks whether the resource has been deleted and is applicable for evaluation.
- check_defined: Helper function to check if a reference is defined.
- get_assume_role_credentials: Assumes a role and returns the credentials.
- inORG: Checks if an account is part of the organization.
- inOU: Checks if an account is part of the organizational unit.
- inDB: Checks if an account matches the specified database ARN.
- evaluate_change_notification_compliance: Evaluates compliance based on change notification.
- lambda_handler: Lambda function entry point.

## Logging

The Lambda function uses the logging package for local logging. Adjust the logging configuration in the code as needed.

## License

This project is licensed under the MIT License.
