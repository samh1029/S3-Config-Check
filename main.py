import json
import logging
import datetime
import os
import boto3
import botocore


# Configuration
AWS_CONFIG_CLIENT = boto3.client('config')
AWS_DYNAMODB_CLIENT = boto3.client('dynamodb')
AWS_ORGANIZATION_CLIENT = boto3.client('organization')
AWS_STS_CLIENT = boto3.client('sts')
ORG_ID = False if str(os.environ.get('ORG_ID')).lower() == "false" else os.environ.get('ORG_ID')
OU_ID = False if str(os.environ.get('OU_ID')).lower() == "false" else os.environ.get('OU_ID')
USE_DB = False if str(os.environ.get('USE_DB')).lower() == "false" else True
DATABASE_ARN = False if str(os.environ.get('DATABASE_ARN')).lower() == "false" else os.environ.get('DATABASE_ARN')

# Set up logging
logging.basicConfig(level=logging.INFO)


def get_aws_account_id():
    """
    Retrieves the AWS account ID.

    Returns:
        str: AWS account ID.
    """
    return boto3.client('sts').get_caller_identity().get('Account')


def is_oversized_changed_notification(message_type):
    """
    Checks if the message type is 'OversizedConfigurationItemChangeNotification'.

    Args:
        message_type (str): The message type.

    Returns:
        bool: True if it's an OversizedConfigurationItemChangeNotification, otherwise False.
    """
    check_defined(message_type, 'messageType')
    return message_type == 'OversizedConfigurationItemChangeNotification'


def get_configuration(resource_type, resource_id, configuration_capture_time):
    """
    Retrieves the configuration item using the getResourceConfigHistory API.

    Args:
        resource_type (str): The type of AWS resource.
        resource_id (str): The ID of the AWS resource.
        configuration_capture_time (datetime): The timestamp to capture the configuration.

    Returns:
        dict: The configuration item.
    """
    result = AWS_CONFIG_CLIENT.get_resource_config_history(
        resourceType=resource_type,
        resourceId=resource_id,
        laterTime=configuration_capture_time,
        limit=1
    )
    configuration_item = result.get('configurationItems')[0]
    return convert_api_configuration(configuration_item)


def convert_api_configuration(configurationItem):
    """
    Converts configuration from the API model to the original invocation model.

    Args:
        configurationItem (dict): The configuration item in API model.

    Returns:
        dict: The converted configuration item.
    """
    for k, v in configurationItem.items():
        if isinstance(v, datetime.datetime):
            configurationItem[k] = str(v)
    configurationItem['awsAccountId'] = configurationItem.get('accountId')
    configurationItem['ARN'] = configurationItem.get('arn')
    configurationItem['configurationStateMd5Hash'] = configurationItem.get('configurationItemMD5Hash')
    configurationItem['configurationItemVersion'] = configurationItem.get('version')
    configurationItem['configuration'] = json.loads(configurationItem.get('configuration'))
    if 'relationships' in configurationItem:
        for i in range(len(configurationItem['relationships'])):
            configurationItem['relationships'][i]['name'] = configurationItem['relationships'][i].get('relationshipName')
    return configurationItem


def get_configuration_item(invokingEvent):
    """
    Gets the configuration item based on the invoking event.

    Args:
        invokingEvent (dict): The invoking event.

    Returns:
        dict: The configuration item.
    """
    check_defined(invokingEvent, 'invokingEvent')
    if is_oversized_changed_notification(invokingEvent.get('messageType')):
        configurationItemSummary = check_defined(invokingEvent.get('configurationItemSummary'), 'configurationItemSummary')
        return get_configuration(configurationItemSummary.get('resourceType'), configurationItemSummary.get('resourceId'), configurationItemSummary.get('configurationItemCaptureTime'))
    return check_defined(invokingEvent.get('configurationItem'), 'configurationItem')


def is_applicable(configurationItem, event):
    """
    Checks whether the resource has been deleted.

    Args:
        configurationItem (dict): The configuration item.
        event (dict): The event.

    Returns:
        bool: True if the resource is applicable for evaluation, otherwise False.
    """
    try:
        check_defined(configurationItem, 'configurationItem')
        check_defined(event, 'event')
    except:
        return True
    status = configurationItem.get('configurationItemStatus')
    eventLeftScope = event.get('eventLeftScope')
    if status == 'ResourceDeleted':
        logging.info("Resource Deleted, setting Compliance Status to NOT_APPLICABLE.")
    return (status == 'OK' or status == 'ResourceDiscovered') and not eventLeftScope


def check_defined(reference, reference_name):
    """
    Helper function to check if a reference is defined.

    Args:
        reference: The reference to check.
        reference_name (str): The name of the reference.

    Returns:
        reference: The reference if defined.

    Raises:
        Exception: If the reference is not defined.
    """
    if not reference:
        raise Exception('Error: ', reference_name, 'is not defined')
    return reference


def get_assume_role_credentials(role_arn):
    """
    Assumes a role and returns the credentials.

    Args:
        role_arn (str): The ARN of the IAM role.

    Returns:
        dict: The assumed role credentials.
    """
    try:
        assume_role_response = AWS_STS_CLIENT.assume_role(RoleArn=role_arn, RoleSessionName="configLambdaExecution")
        return assume_role_response.get('Credentials')
    except botocore.exceptions.ClientError as ex:
        if 'AccessDenied' in ex.response.get('Error').get('Code'):
            ex.response['Error']['Message'] = "AWS Config does not have permission to assume the IAM role."
        else:
            ex.response['Error']['Message'] = "InternalError"
            ex.response['Error']['Code'] = "InternalError"
        raise ex


def inORG(account):
    if account == ORG_ID:
        return 'COMPLIANT'
    else:
        return 'NON_COMPLIANT'


def inOU(account):
    if account == OU_ID:
        return 'COMPLIANT'
    else:
        return 'NON_COMPLIANT'


def inDB(account):
    if account == DATABASE_ARN:
        return 'COMPLIANT'
    else:
        return 'NON_COMPLIANT'


def evaluate_change_notification_compliance(configuration_item, rule_parameters):
    """
    Evaluates compliance based on change notification.

    Args:
        configuration_item (dict): The configuration item.
        rule_parameters (dict): The rule parameters.

    Returns:
        str: The compliance status ('COMPLIANT', 'NON_COMPLIANT', 'NOT_APPLICABLE').
    """
    check_defined(configuration_item, 'configuration_item')
    check_defined(configuration_item.get('configuration'), 'configuration_item[\'configuration\']')

    if rule_parameters:
        check_defined(rule_parameters, 'rule_parameters')
        logging.info(f'Rule Params: {rule_parameters}')

    if (configuration_item.get('resourceType') != 'AWS::S3::Bucket'):
        return 'NOT_APPLICABLE'

    else:
        try:
            policy = json.loads(configuration_item.get('supplementaryConfiguration').get('BucketPolicy').get('policyText'))
        except:
            return 'COMPLIANT'

        accounts = []
        for statement in policy.get('Statement'):
            for principal in statement.get('Principal'):
                p = statement.get('Principal').get(principal)
                if isinstance(p, list):
                    for line in p:
                        accounts.append(line.split(':')[4])
                else:
                    accounts.append(p.split(':')[4])

        compliance = []

        for account in accounts:
            if ORG_ID:
                compliance.append(inORG(account))
            if OU_ID:
                compliance.append(inOU(account))
            if USE_DB:
                compliance.append(inDB(account))
        return "NON_COMPLIANT" if 'NON_COMPLIANT' in compliance else "COMPLIANT"


def lambda_handler(event, context):
    """
    Lambda function entry point.

    Args:
        event (dict): The Lambda event.
        context (object): The Lambda context.

    Returns:
        dict: The Lambda response.
    """
    compliance_value = 'NOT_APPLICABLE'
    changedProperties = False

    check_defined(event, 'event')
    invoking_event = json.loads(event.get('invokingEvent'))

    rule_parameters = {}
    if 'ruleParameters' in event:
        rule_parameters = json.loads(event.get('ruleParameters'))

    configuration_item = get_configuration_item(invoking_event)
    try:
        changedProperties = True if invoking_event.get("configurationItemDiff").get("changedProperties").get("SupplementaryConfiguration.BucketPolicy.PolicyText") else False
    except:
        pass

    if is_applicable(configuration_item, event) and changedProperties:
        compliance_value = evaluate_change_notification_compliance(configuration_item, rule_parameters)
    else:
        logging.info('Not a policy change. Ignoring.')
        return

    configItem = invoking_event.get('configurationItem')

    logging.info(f'ComplianceResourceType: {configItem.get('resourceType')}')
    logging.info(f'ComplianceResourceId: {configItem.get('resourceId')}')
    logging.info(f'ComplianceType: {compliance_value}')

    response = AWS_CONFIG_CLIENT.put_evaluations(
        Evaluations=[
            {
                'ComplianceResourceType': configItem.get('resourceType'),
                'ComplianceResourceId': configItem.get('resourceId'),
                'ComplianceType': compliance_value,
                'OrderingTimestamp': configItem.get('configurationItemCaptureTime')
            },
        ],
        ResultToken=event.get('resultToken')
        )
    return response
