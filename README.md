# iam-policy-scanner
Scans IAM Policies and Roles for Possible Security Issues

This script has a number of predefined variables for tuning purposes.

Some recommended use cases are:
* Scan all your Customer Managed Policies
* Scan any "attached" AWS Managed Policies
* Scan policies attached to your roles

To use, install "colorama" if needed:
```
pip3 install colorama
```
(This is just used when printing to the console)

Modify the role name on (or near) line 416, to be a role that exists within your account.

Then run the script as follows:
```
python3 scan_policies.py
```

After running it, you can modify the variables such as: star_resource_only, target_services, skip_if_has_condition to get as many or as few results as you'd like.
