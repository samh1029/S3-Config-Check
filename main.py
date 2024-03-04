import json
import datetime
import os

import boto3
import botocore


# Check whether the message is OversizedConfigurationItemChangeNotification or not
def is_oversized_changed_notification(message_type):
    check_defined(message_type, 'messageType')
    return message_type == 'OversizedConfigurationItemChangeNotification'

# Get configurationItem using getResourceConfigHistory API
# in case of OversizedConfigurationItemChangeNotification
def get_configuration(resource_type, resource_id, configuration_capture_time):
    result = AWS_CONFIG_CLIENT.get_resource_config_history(
        resourceType=resource_type,
        resourceId=resource_id,
        laterTime=configuration_capture_time,
        limit=1)
    configurationItem = result.get('configurationItems')[0]
    return convert_api_configuration(configurationItem)

# Convert from the API model to the original invocation model
def convert_api_configuration(configurationItem):
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


# Based on the type of message get the configuration item
# either from configurationItem in the invoking event
# or using the getResourceConfigHistory API in getConfiguration function.
def get_configuration_item(invokingEvent):
    check_defined(invokingEvent, 'invokingEvent')
    if is_oversized_changed_notification(invokingEvent.get('messageType')):
        configurationItemSummary = check_defined(invokingEvent.get('configurationItemSummary'), 'configurationItemSummary')
        return get_configuration(configurationItemSummary.get('resourceType'), configurationItemSummary.get('resourceId'), configurationItemSummary.get('configurationItemCaptureTime'))
    return check_defined(invokingEvent.get('configurationItem'), 'configurationItem')

# Check whether the resource has been deleted. If it has, then the evaluation is unnecessary.
def is_applicable(configurationItem, event):
    try:
        check_defined(configurationItem, 'configurationItem')
        check_defined(event, 'event')
    except:
        return True
    status = configurationItem.get('configurationItemStatus')
    eventLeftScope = event.get('eventLeftScope')
    if status == 'ResourceDeleted':
        print("Resource Deleted, setting Compliance Status to NOT_APPLICABLE.")
    return (status == 'OK' or status == 'ResourceDiscovered') and not eventLeftScope

# Helper function used to validate input
def check_defined(reference, reference_name):
    if not reference:
        raise Exception('Error: ', reference_name, 'is not defined')
    return reference

def get_assume_role_credentials(role_arn):
    sts_client = boto3.client('sts')
    try:
        assume_role_response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="configLambdaExecution")
        return assume_role_response.get('Credentials')
    except botocore.exceptions.ClientError as ex:
        # Scrub error message for any internal account info leaks
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
    check_defined(configuration_item, 'configuration_item')
    check_defined(configuration_item.get('configuration'), 'configuration_item[\'configuration\']')

    if rule_parameters:
        check_defined(rule_parameters, 'rule_parameters')
        print(f'Rule Params: {rule_parameters}')

    # We are only interested if it is a S3 bucket AND the bucket policy has changed
    if (configuration_item.get('resourceType') != 'AWS::S3::Bucket'):
        return 'NOT_APPLICABLE'

    else:
        # Get bucket policy
        try:
            policy = json.loads(configuration_item.get('supplementaryConfiguration').get('BucketPolicy').get('policyText'))
        except: # if no policy defined then it must be compliant
            return 'COMPLIANT'

        # Locate Accounts defined in bucket policy
        accounts = []
        for statement in policy.get('Statement'):
            for principal in statement.get('Principal'):
                p = statement.get('Principal').get(principal)
                # Handle multiple vs single principals in the policy
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
        print(compliance)
        return "NON_COMPLIANT" if 'NON_COMPLIANT' in compliance else "COMPLIANT"

def lambda_handler(event, context):

    global AWS_CONFIG_CLIENT
    global AWS_DYNAMODB_CLIENT
    global AWS_ORGANIZATION_CLIENT
    global ACCOUNT_ID
    global ORG_ID
    global OU_ID
    global USE_DB
    global DATABASE_ARN

    AWS_CONFIG_CLIENT = boto3.client('config')
    AWS_DYNAMODB_CLIENT = boto3.client('dynamodb')
    AWS_ORGANIZATION_CLIENT = boto3.client('organization')

    ACCOUNT_ID = boto3.client('sts').get_caller_identity().get('Account')

    ORG_ID = False if str(os.environ.get('ORG_ID')).lower() == "false" else os.environ.get('ORG_ID')
    OU_ID = False if str(os.environ.get('OU_ID')).lower() == "false" else os.environ.get('OU_ID')
    USE_DB = False if str(os.environ.get('USE_DB')).lower() == "false" else True
    DATABASE_ARN = False if str(os.environ.get('DATABASE_ARN')).lower() == "false" else os.environ.get('DATABASE_ARN')

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
        print('Not a policy change. Ignoring.')
        return

    configItem = invoking_event.get('configurationItem')

    print(f'ComplianceResourceType: {configItem.get('resourceType')}')
    print(f'ComplianceResourceId: {configItem.get('resourceId')}')
    print(f'ComplianceType: {compliance_value}')

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
