'''
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License.

#####################################
##           Gherkin               ##
#####################################

File Name:
    scan_policies.py

Version:
    0.1 Beta, bugs likely.  Please report any bugs by contacting me on GitHub.

Author:
    Nicholas M. Gilbert (NickTheSecurityDude)

Description:
    Scans IAM policies, reporting on user defined conditions which may pose a security issue.

Usage:
    pip3 install colorama
    python3 scan_policies.py
    This prints the results to the console, alternatively you can modify it to print in json format, or write to a pickledb.

Purpose:
    In order to: enforce least privilege and prevent privilege escalation
             As: a Security Officer
         I want: run an automated scan of all IAM policies.

Flags and Variables:
              check_not_action: Flag to alert for policies which have "NotAction"
            check_not_resource: Flag to alert for policies which have "NotResource"
            star_resource_only: Only check if the resource is "*". IE. Skip if resource is scoped
         skip_if_has_condition: Skip if policy statement has a condition.  Note: setting to 1 will return less results but may result in false negatives
               target_services: Alert on any actions within the service
                target_actions: Alert on any policies with the listed actions
        target_action_patterns: Alert on any policies with actions that start with the list pattern
           whitelisted_actions: Don't alert on actions in this list
    privileged_policy_patterns: Policies which are obviously privileged based on their name
           deprecated_policies: List deprecated policies if you want to skip them (not recommended when checking policies attached to roles)
                         scope: When checking managed policies, select AWS created (AWS), Customer Managed (Local), or All (All)
        attached_policies_only: True if you only want to scan attached policies, False if you want it to scan all policies
            skip_service_roles: Skips service roles if set to 1
                   
Scans the following:
    AWS::IAM::Role
    AWS::IAM::Policy

Scenarios:
    The following examples are provided.

    Example 1:
        Check managed policies, scans all managed policies, set the "scope" variable as desired.

    Example 2:
        Check policies attached to a single role.
        Set the variable called "role_name"

    Example 3:
        Check policies attached to all roles.

'''

import os,json,boto3
from colorama import Fore, Back, Style

# Functions which does the policy scanning
def scan_policy(policy_name, policy_statements, target_services, target_actions, target_action_patterns, check_not_resource, 
                check_not_action, star_resource_only, skip_if_has_condition, whitelisted_actions):

  # Variables
  target_services=target_services
  target_actions=target_actions
  target_action_patterns=target_action_patterns

  policy_scan_results=[]

  # get statements
  statements=policy_statements
  statements_arr=[]

  # check if statement is string or list
  if type(statements)==list:
    statements_arr=statements
  else:
    statements_arr.append(statements)

  # loop through statements
  for statement in statements_arr:

    # get effect Allow / Deny
    effect=statement['Effect']

    not_action=0
    not_resource=0
    star_resource=0
    has_condition=0

    if effect=='Allow':

      # Check if Resource / NotResource
      try:
        actions=statement['Resource']
      except:
        if check_not_resource:
          policy_scan_results.append({"rule": "NotResource Found", "action": ""})
        not_resource=1

      # check if any resource contains "*"
      if not not_resource:
        resources=statement['Resource']
        if type(resources) == list:
          for resource in resources:
            if resource == "*":
              star_resource=1
        elif resources == "*":
          star_resource=1

      # Check if condition is present
      try:
        condition=statement['Condition']
        has_condition=1
      except:
        # no condition found
        pass
      

      # Check if Action / NotAction
      try:
        actions=statement['Action']
      except:
        if check_not_action:
          policy_scan_results.append({"rule": "NotAction Found", "action": ""})
        not_action=1

      actions_arr=[]

      # check if action is string or list
      if type(actions)==list:
        actions_arr=actions
      else:
        actions_arr.append(actions)

      # loop through actions
      if not not_action and not not_resource:      
        if (not star_resource_only or star_resource) and not (skip_if_has_condition and has_condition):
          for action in actions_arr: 
            action=action.lower()
            service=action.split(":")[0]

            # Check if action is whitelisted
            if action not in whitelisted_actions:
 
              # check if service in target_services
              if len(target_services) > 0:
                if service in target_services:
                  policy_scan_results.append({"rule": "Action in Target Service Found", "action": action})

              # check if action in target_actions
              if len(target_actions) > 0:
                if action in target_actions:
                  policy_scan_results.append({"rule": "Target Action Found", "action": action})

              # check if action in target_action_patterns
              if len(target_action_patterns) > 0:
                for pattern in target_action_patterns:
                  if pattern in action:
                    policy_scan_results.append({"rule": "Target Action Pattern Found", "action": action})
     
  return policy_scan_results

# get inline policies
def get_inline_policies(role_name):  

  # Get Role's Inline Policies
  response = iam_client.list_role_policies(
    RoleName=role_name
  )

  return response['PolicyNames']

# get managed policies
def get_managed_policies(role_name):

  # Get Role's Managed Policies
  response = iam_client.list_attached_role_policies(
    RoleName=role_name
  )

  return response['AttachedPolicies']

# get managed policy statements
def get_managed_policy_statements(policy_arn):

  # Get policy version
  policy_version=response = iam_client.get_policy(
    PolicyArn=policy_arn
  )['Policy']['DefaultVersionId']

  # Get policy document's statements
  response = iam_client.get_policy_version(
    PolicyArn=policy_arn,
    VersionId=policy_version
  )
 
  policy_statements=response['PolicyVersion']['Document']['Statement']

  return policy_statements  



# check role 
def check_role(role_name,target_services, target_actions, target_action_patterns, check_not_resource, check_not_action, star_resource_only, 
               skip_if_has_condition, privileged_policy_patterns, deprecated_policies, whitelisted_actions):

  # Variables
  target_services=target_services
  target_actions=target_actions
  target_action_patterns=target_action_patterns
  check_not_resource=check_not_resource
  check_not_action=check_not_action
  star_resource_only=star_resource_only
  skip_if_has_condition=skip_if_has_condition
  privileged_policy_patterns=privileged_policy_patterns
  deprecated_policies=deprecated_policies

  # Dict for results
  results={}

  # Check inline policies
  inline_policies=get_inline_policies(role_name)
  for policy_name in inline_policies:
    response = iam_client.get_role_policy(
      RoleName=role_name,
      PolicyName=policy_name
    )
    policy_statements=response['PolicyDocument']['Statement']

    # Scan Policy
    result=scan_policy(policy_name, policy_statements, target_services, target_actions, target_action_patterns, check_not_resource, check_not_action,
                       star_resource_only, skip_if_has_condition, whitelisted_actions)

    # If any results, add to dict
    if len(result) > 0:
      results[policy_name]=result

  # Check managed policies
  managed_policies=get_managed_policies(role_name)
  for policy in managed_policies:
    policy_name=policy['PolicyName']
    policy_arn=policy['PolicyArn']

    # Get Policy Arn
    policy_statements=get_managed_policy_statements(policy_arn)

    # Scan Policy
    result=scan_policy(policy_name, policy_statements, target_services, target_actions, target_action_patterns, check_not_resource, check_not_action,
                       star_resource_only, skip_if_has_condition, whitelisted_actions)

    # If any results, add to dict
    if len(result) > 0:
      results[policy_name]=result    

    # Check for privileged managed policies
    for pattern in privileged_policy_patterns:
      if pattern in policy_name and pattern != "ServiceRole":
        try:
          results[policy_name].append({"rule": "Privileged Policy Pattern Found", "policy": policy_name})
        except:
          results[policy_name]=[{"rule": "Privileged Policy Pattern Found", "policy": policy_name}]

    # Check for attached deprecated policies
    if policy_name in deprecated_policies:
      try:
        results[policy_name].append({"rule": "Deprecated Policy Found", "policy": policy_name})
      except:
        results[policy_name]=[{"rule": "Deprecated Policy Found", "policy": policy_name}]
  
  # Return the dict
  return results

# print function
def print_policy_results(results,tabs=1):

  # Tabs for nice formatting
  if tabs==1:
    p_tabs=""
    tabs="\t"
  if tabs==2:
    p_tabs="\t"
    tabs="\t\t"

  # Loop through results
  for result in results:
    print(Fore.MAGENTA,p_tabs+"Policy Name:",result)
    rules=results[result]
    
    # Loop through rules
    for rule in rules:
      try:
        print(Fore.BLUE,tabs+rule['rule']+":",rule['action'])
      except:
        print(Fore.BLUE,tabs+rule['rule']+":",rule['policy'])

  print(Style.RESET_ALL) 

# Function to print role results
def print_role_results(role_results):

  # Loop through roles
  for result in role_results:        
    print(Fore.CYAN,"Role Name:",result)
    # Print policies
    print_policy_results(role_results[result],2)

# main routine
if __name__ == "__main__":

  iam_client = boto3.client('iam')

  # Arrays, use all lowercase (leave empty to skip check)

  # services to check
  target_services=["iam","lambda","s3","kms"]
  # skip target services
  target_services=[]

  # actions to check
  target_actions=["*","iam:*","iam:passrole","kms:decrypt","lambda:create*","lambda:createfunction","lambda:get*","lambda:getfunction",
                  "lambda:invokefunction","lambda:update*","s3:*","s3:get*","s3:getobject","lambda:*"]

  # action patterns to check
  target_action_patterns=["iam:create","iam:update"]

  # whitelisted actions
  whitelisted_actions=["iam:createservicelinkedrole"] 

  # privileged policy patterns, ex privileged policies
  privileged_policy_patterns=["FullAccess","Admin","PowerUser","ReadOnlyAccess","ServiceRole"]

  # skip (depreated) policies
  deprecated_policies=["AmazonEC2RoleforSSM","AWSConfigRole"]

  # variables
  check_not_resource=0
  check_not_action=0
  star_resource_only=1
  skip_if_has_condition=1
  
  # skip privileged policies
  skip_privileged=1
  
  # skip deprecated policies
  skip_depreacted=1

  # Check only policies which are attached
  attached_policies_only=False

  # select scope: 'All'|'AWS'|'Local',  Local = customer managed
  scope='Local'

  """
  # Dict for results
  results={}

  # Example 1, check managed policies
  print("Checking Managed Policies:",scope)

  # Paginator
  p=iam_client.get_paginator('list_policies')
  paginator=p.paginate(Scope=scope,OnlyAttached=attached_policies_only)

  # Loop through pages
  for page in paginator:
   
    # Loop through policies
    for policy in page['Policies']: 
      policy_name=policy['PolicyName']
      policy_arn=policy['Arn']

      skip=0

      # Deprecated policy check
      if skip_depreacted and policy_name in deprecated_policies:
        skip=1

      # Privileged policy pattern check
      if skip_privileged:
        for priv in privileged_policy_patterns:
          if priv in policy_name:
            skip=1

      # Check the policy
      if not skip:
        policy_statements=get_managed_policy_statements(policy_arn)
        result=scan_policy(policy_name, policy_statements, target_services, target_actions, target_action_patterns, check_not_resource, check_not_action,
                           star_resource_only, skip_if_has_condition, whitelisted_actions)

        # if any results append to results  
        if len(result) > 0:
          results[policy_name]=result

  # Print the results
  print(len(results),"results found")
  print_policy_results(results)
 
  # Example 2, check all policies attached to a particular role

  # Variables
  target_services=[]
  target_action_patterns=[]
  skip_if_has_condition=0
  star_resource_only=1

  # Put the role you want to check here
  role_name="MyInsecureRole"
  print("Checking single role")

  role_results=check_role(role_name,target_services, target_actions, target_action_patterns, check_not_resource, check_not_action,
                          star_resource_only, skip_if_has_condition, privileged_policy_patterns, deprecated_policies, whitelisted_actions)

  # Print the results
  print(Fore.CYAN,"Role Name:",role_name)
  print_policy_results(role_results,2)

  """  
  # Example 3, check all roles

  # Set to 1 to skip service roles
  skip_service_roles=1

  # Option A: Intensive Scan
  # Uses above settings

  # Option B: Single Permission Scan
  target_services=[]
  target_actions=["s3:putobject"]
  #target_action_patterns=[]
  target_action_patterns=["ec2:modify"]
  whitelisted_actions=[]
  privileged_policy_patterns=[]
  deprecated_policies=[]

  # variables
  check_not_resource=0
  check_not_action=0
  star_resource_only=1
  skip_if_has_condition=1
  skip_privileged=1
  skip_depreacted=1

  print("Checking all roles")

  # Dict for results
  all_roles={}

  # Paginator
  p=iam_client.get_paginator('list_roles')
  paginator=p.paginate()  

  # Loop through pages
  for page in paginator:
    roles=page['Roles']

    # Loop through roles
    for role in roles:
      role_name=role['RoleName']
      if "ServiceRole" not in role_name and "AWSReservedSSO" not in role_name and "aws-controltower" not in role_name and "AWSControlTower" not in role_name:
        role_results=check_role(role_name,target_services, target_actions, target_action_patterns, check_not_resource, check_not_action,
                                star_resource_only, skip_if_has_condition, privileged_policy_patterns, deprecated_policies, whitelisted_actions )
      
        # If there was a result, add it to dict
        if role_results != {}:
          all_roles[role_name]=role_results

  # Print the results
  print(len(all_roles),"results found")
  print_role_results(all_roles)

