# Google Workspace Alerts Wodle for Wazuh

## Overview

This wodle allows security teams to monitor security alerts raised in Google Workspace environments through their existing Wazuh deployment.

- Fetches alerts from the Google Workspace Alert Center API
- Processes [over 40](https://github.com/rh0dy/google-workspace-alerts-wodle/blob/main/config.py#L25-L69) different [alert types](https://developers.google.com/admin-sdk/alertcenter/reference/alert-types) from Google Workspace, including phishing reports, leaked passwords, suspicious logins, government attack warnings, devices compromised, data loss prevention,s primary admin changes, super admin password resets, SSO profile changes, drive settings changes, new users added, account suspension warnings, and many more
- Maintains state between runs to avoid duplicate alerts
- Flattens complex alert structures for Wazuh compatibility

## Requirements

- Wazuh server (version 4.x or higher)
- Python 3.10+
- Google Workspace with Alert Center
- Google Cloud Platform project with the Admin SDK API enabled and a service account (see below)

## Google API Authentication

**Important**: This wodle requires Google API credentials to communicate with Google Workspace through a delegated administrator account. It's a bit fiddly to set up as there are a few layers to it, the [Google dev docs](https://developers.google.com/workspace/guides/get-started) have detailed instructions on how to do it, but the abridged version is as follows:

1. Create a [Google Cloud project](https://developers.google.com/workspace/guides/create-project)
2. Switch scope to the project you just created
3. Enable the [Google Workspace Alert Center API](https://developers.google.com/workspace/guides/enable-apis)
4. Create a [service account](https://developers.google.com/workspace/guides/create-credentials#service-account) with "domain-wide delegation" (this authorises access to your Google Workspace's data on behalf of user in the Google Workspace domain, ideally through a non-human "service account" user)
5. In the domain-wide delegation [settings](https://developers.google.com/identity/protocols/oauth2/service-account#delegatingauthority), add the following scope `https://www.googleapis.com/auth/apps.alerts`
6. Retrieve and save the service account's [credentials](https://developers.google.com/workspace/guides/create-credentials#create_credentials_for_a_service_account), which will be used later in the wodle's config file

## Installation

1. Clone this repo and copy the files to your Wazuh server's wodle directory:

```bash
sudo mkdir -p /var/ossec/wodles/google_workspace_alerts
sudo cp -r * /var/ossec/wodles/google_workspace_alerts/
```

2. Install the required Python dependencies on your Wazuh server:

```bash
sudo /var/ossec/framework/python/bin/pip3 install google-api-python-client google-auth google-auth-httplib2
```

3. Update the config file with your Google API credentials (see below):

```bash
vim /var/ossec/wodles/google_workspace_alerts/config.json
```

4. Make the wodle shell script executable:

```bash
sudo chmod +x /var/ossec/wodles/google_workspace_alerts/google-workspace-alerts
```

5. Update your Wazuh configuration `/var/ossec/etc/ossec.conf` to include the wodle:

```xml
  <!-- Add this to your Wazuh ossec.conf file in the group section -->
  <wodle name="command">
    <disabled>no</disabled>
    <tag>google-workspace-alerts</tag>
    <command>/var/ossec/wodles/google_workspace_alerts/google_workspace_alerts</command>
    <interval>10m</interval>
    <ignore_output>no</ignore_output>
    <run_on_start>yes</run_on_start>
    <timeout>0</timeout>
  </wodle>
```

6. Add a custom rule to display the Google Workspace alerts in Wazuh. This can be added to `/var/ossec/etc/rules/local_rules.xml` (may get overriden after upgrading Wazuh) or in a separate rule file here `/var/ossec/ruleset/rules/`:

```xml
<group name="google_workspace,">
  <rule id="100000" level="5">
    <decoded_as>json</decoded_as>
    <field name="wodle">google-workspace-alerts</field>
    <description>Google Workspace Alert: $(source) - $(type)</description>
    <group>google_workspace_alert,</group>
  </rule>
</group>
```

7. Restart Wazuh to apply the changes:

```bash
/var/ossec/bin/wazuh-control restart
```

## Testing

You can run the wodle manually for testing:

```bash
/var/ossec/wodles/google_workspace_alerts/google-workspace-alerts --config /path/to/config.json
```

## Configuration

This wodle requires Google API credentials to be set to communicate with Google Workspace through a delegated administrator account, the majority of these settings are found in the service account's [credentials](https://developers.google.com/workspace/guides/create-credentials#create_credentials_for_a_service_account) and are set in `/var/ossec/wodles/google_workspace_alerts/config.json`.

| Setting | Description | Required | Example |
|---------|-------------|----------|---------|
| `project_id` | Google Cloud project identifier | ✅ | `"my-project-123456"` |
| `private_key_id` | Private key ID for your Google Cloud project service account | ✅ | `"a1b2c3d4e5f6g7h8i9j0"` |
| `private_key` | Private key for your Google Cloud project service account | ✅ | `"-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgk...\n-----END PRIVATE KEY-----\n"` |
| `client_email` | Email for your Google Cloud project service account  | ✅ | `"my-service-account@my-project-123456.iam.gserviceaccount.com"` |
| `client_id` | Client identifier for your Google Cloud project service account | ✅ | `"123456789012345678901"` |
| `client_x509_cert_url` | URL for the certificate for your Google Cloud project service account | ✅ | `"https://www.googleapis.com/robot/v1/metadata/x509/my-service-account%40my-project-123456.iam.gserviceaccount.com"` |
| `delegated_account`* | Google Workspace admin account with appropriate privileges | ✅ | `"admin@yourdomain.com"` |
| `log_file` | Path to log file (defaults to `/var/ossec/logs/google_workspace_alerts_wodle.log`) | ❌ | `"/var/log/wodle.log"` |
| `log_level` | Logging verbosity level (defaults to `info`) | ❌ | `"info"` |
| `state_file` | Path to state persistence file (defaults to `/var/ossec/var/google_workspace_alerts_wodle_state.json`) | ❌ | `"/var/lib/wodle/state.json"` |

\* The `delegated_account` must be a Google Workspace administrator with the necessary permissions to perform the required operations.

## State Management

This wodle maintains its state in a JSON file to avoid processing the same alerts multiple times. The state file contains:
- The timestamp of the last processed alert
- A set of processed alert IDs (up to 10,000)

If no state file exists, the wodle will fetch alerts from the last 24 hours.
