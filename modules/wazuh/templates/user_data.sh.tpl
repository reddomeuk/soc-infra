#!/bin/bash
# File: modules/wazuh/templates/user_data.sh.tpl

# Exit immediately if a command exits with a non-zero status
set -e

# Log all output
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

echo "Starting Wazuh installation process..."

# Update system
yum update -y
yum install -y amazon-cloudwatch-agent jq curl wget unzip python3 python3-pip

# Install AWS CLI
pip3 install --upgrade awscli

# Set hostname
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
hostnamectl set-hostname ${node_name}-$INSTANCE_ID

# Install Wazuh manager
echo "Installing Wazuh manager..."
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF

# Install Wazuh manager
yum -y install wazuh-manager-${wazuh_version}

# Configure Wazuh
echo "Configuring Wazuh..."
mkdir -p /var/ossec/etc/

# Backup original configuration
cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak

# Create Wazuh configuration
cat > /var/ossec/etc/ossec.conf << EOF
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>smtp.example.wazuh.com</smtp_server>
    <email_from>wazuh@example.wazuh.com</email_from>
    <email_to>recipient@example.wazuh.com</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
    <agents_disconnection_time>10m</agents_disconnection_time>
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <!-- Choose between "plain", "json", or "plain,json" for the format of internal logs -->
  <logging>
    <log_format>plain</log_format>
  </logging>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <!-- Policy monitoring -->
  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>

    <!-- Frequency that rootcheck is executed - every 12 hours -->
    <frequency>43200</frequency>

    <rootkit_files>/var/ossec/etc/rootcheck/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>

    <skip_nfs>yes</skip_nfs>
  </rootcheck>

  <wodle name="aws-s3">
    <disabled>no</disabled>
    <interval>10m</interval>
    <run_on_start>yes</run_on_start>
    <bucket type="cloudtrail">${s3_bucket}/cloudtrail</bucket>
    <bucket type="guardduty">${s3_bucket}/guardduty</bucket>
    <bucket type="vpcflow">${s3_bucket}/vpcflow</bucket>
    <bucket type="config">${s3_bucket}/config</bucket>
    <bucket type="custom">${s3_bucket}/alb</bucket>
    <bucket type="custom">${s3_bucket}/loadbalancer</bucket>
    <access_key>none</access_key>
    <secret_key>none</secret_key>
    <remove_from_bucket>no</remove_from_bucket>
    <skip_on_error>yes</skip_on_error>
  </wodle>

  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
  </wodle>

  <wodle name="vulnerability-detector">
    <disabled>no</disabled>
    <interval>5m</interval>
    <run_on_start>yes</run_on_start>
    <update_interval>1h</update_interval>
    <provider name="nvd">
      <enabled>yes</enabled>
      <update_interval>1h</update_interval>
    </provider>
    <provider name="redhat">
      <enabled>yes</enabled>
      <update_interval>1h</update_interval>
    </provider>
    <provider name="canonical">
      <enabled>yes</enabled>
      <update_interval>1h</update_interval>
    </provider>
    <provider name="debian">
      <enabled>yes</enabled>
      <update_interval>1h</update_interval>
    </provider>
  </wodle>

  <!-- File integrity monitoring -->
  <syscheck>
    <disabled>no</disabled>

    <!-- Frequency that syscheck is executed default every 12 hours -->
    <frequency>43200</frequency>

    <scan_on_start>yes</scan_on_start>

    <!-- Directories to check  (perform all possible verifications) -->
    <directories>/etc,/usr/bin,/usr/sbin</directories>
    <directories>/bin,/sbin,/boot</directories>

    <!-- Files/directories to ignore -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>
    <ignore>/sys/kernel/security</ignore>
    <ignore>/sys/kernel/debug</ignore>

    <!-- Check if the MD5, SHA1 or SHA256 sum changed in the registry entries -->
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\batfile</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\cmdfile</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\comfile</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\exefile</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\piffile</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\AllFilesystemObjects</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\Directory</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\Folder</windows_registry>
    <windows_registry>\Registry\Machine\Software\Classes\batfile</windows_registry>
    <windows_registry>\Registry\Machine\Software\Classes\cmdfile</windows_registry>
    <windows_registry>\Registry\Machine\Software\Classes\comfile</windows_registry>
    <windows_registry>\Registry\Machine\Software\Classes\exefile</windows_registry>
    <windows_registry>\Registry\Machine\Software\Classes\piffile</windows_registry>
    <windows_registry>\Registry\Machine\Software\Classes\AllFilesystemObjects</windows_registry>
    <windows_registry>\Registry\Machine\Software\Classes\Directory</windows_registry>
    <windows_registry>\Registry\Machine\Software\Classes\Folder</windows_registry>

    <!-- Windows registry entries to ignore -->
    <registry_ignore>HKEY_LOCAL_MACHINE\Security\Policy\Secrets</registry_ignore>
    <registry_ignore>HKEY_LOCAL_MACHINE\Security\SAM\Domains\Account\Users</registry_ignore>
    <registry_ignore>\Registry\Machine\Security\Policy\Secrets</registry_ignore>
    <registry_ignore>\Registry\Machine\Security\SAM\Domains\Account\Users</registry_ignore>

    <!-- Frequency for file modifications -->
    <file_ignore>queue_.*</file_ignore>
  </syscheck>

  <global>
    <cluster>
      <name>wazuh</name>
      <node_name>${node_name}</node_name>
      <node_type>${node_type}</node_type>
      <key>${cluster_key}</key>
      <port>1516</port>
      <bind_addr>0.0.0.0</bind_addr>
      <nodes>
        <node>wazuh-master</node>
      </nodes>
      <hidden>no</hidden>
      <disabled>no</disabled>
    </cluster>
  </global>

  <!-- Active response -->
  <active-response>
    <disabled>no</disabled>
    <ca_store>/var/ossec/etc/wpk_root.pem</ca_store>
    <ca_verification>yes</ca_verification>
  </active-response>

  <!-- Choose between plain or json format (or both) for internal logs -->
  <logging>
    <log_format>plain</log_format>
  </logging>

  <integration>
    <name>custom-s3</name>
    <hook_url>http://127.0.0.1:8000/sample</hook_url>
    <level>10</level>
    <group>authentication_success,authentication_failed</group>
    <api_key>xxxxxx</api_key>
  </integration>

  <!-- Analysis configuration -->
  <ruleset>
    <!-- Default ruleset -->
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
    <list>etc/lists/security-eventchannel</list>

    <!-- User-defined ruleset -->
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>

  <!-- Configuration for wazuh-authd -->
  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <force_insert>yes</force_insert>
    <force_time>0</force_time>
    <purge>yes</purge>
    <use_password>no</use_password>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <!-- <ssl_agent_ca></ssl_agent_ca> -->
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>/var/ossec/etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>/var/ossec/etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>
</ossec_config>
EOF

# Configure Wazuh API
echo "Configuring Wazuh API..."
yum -y install wazuh-indexer-${wazuh_version}
yum -y install wazuh-dashboard-${wazuh_version}

# Install Filebeat for shipping logs to Elasticsearch
echo "Installing Filebeat..."
rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch
cat > /etc/yum.repos.d/elastic.repo << EOF
[elasticsearch-7.x]
name=Elasticsearch repository for 7.x packages
baseurl=https://artifacts.elastic.co/packages/7.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF

yum -y install filebeat-7.10.2

# Configure Filebeat
echo "Configuring Filebeat..."
curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/4.x/resources/elastic-stack/filebeat/7.x/filebeat.yml
curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh-documentation/4.x/resources/elastic-stack/filebeat/7.x/wazuh-template.json
curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.2.tar.gz | tar -xvz -C /usr/share/filebeat/module

# Configure Filebeat to use AWS Elasticsearch
cat > /etc/filebeat/filebeat.yml << EOF
output.elasticsearch:
  hosts: ["${elasticsearch_endpoint}:443"]
  protocol: "https"
  username: "admin"
  password: "admin"
  ssl.verification_mode: certificate
setup.template.json.enabled: true
setup.template.json.path: '/etc/filebeat/wazuh-template.json'
setup.template.json.name: 'wazuh'
setup.ilm.overwrite: true
setup.ilm.enabled: false

filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: false
EOF

# Enable and start services
echo "Enabling and starting services..."
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl enable filebeat
systemctl start wazuh-manager
systemctl start filebeat

# Setup password for Wazuh API
echo "Setting up Wazuh API credentials..."
# Create admin user for Wazuh API
API_USER="admin"
API_PASSWORD="${admin_password}"

# Wait for the API to be available
echo "Waiting for Wazuh API to become available..."
until curl -s -k https://localhost:55000/; do
  echo "Wazuh API not available yet, waiting..."
  sleep 10
done

# Create the admin user
echo "Creating admin user for Wazuh API..."
ADMIN_TOKEN=$(curl -k -u wazuh:wazuh -X GET "https://localhost:55000/security/user/authenticate" | jq -r '.data.token')
curl -k -X POST "https://localhost:55000/security/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "'$API_USER'",
    "password": "'$API_PASSWORD'",
    "allow_run_as": true,
    "roles": ["administrator"]
  }'

# Configure CloudWatch agent
echo "Configuring CloudWatch agent..."
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << EOF
{
  "agent": {
    "metrics_collection_interval": 60,
    "run_as_user": "root"
  },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/ossec/logs/alerts/alerts.log",
            "log_group_name": "/wazuh/alerts",
            "log_stream_name": "{instance_id}",
            "timezone": "UTC"
          },
          {
            "file_path": "/var/log/wazuh-manager.log",
            "log_group_name": "/wazuh/manager",
            "log_stream_name": "{instance_id}",
            "timezone": "UTC"
          },
          {
            "file_path": "/var/log/user-data.log",
            "log_group_name": "/wazuh/user-data",
            "log_stream_name": "{instance_id}",
            "timezone": "UTC"
          }
        ]
      }
    }
  },
  "metrics": {
    "metrics_collected": {
      "disk": {
        "measurement": [
          "used_percent"
        ],
        "resources": [
          "/"
        ]
      },
      "mem": {
        "measurement": [
          "mem_used_percent"
        ]
      }
    },
    "append_dimensions": {
      "InstanceId": "\${aws:InstanceId}"
    }
  }
}
EOF

# Start CloudWatch agent
systemctl enable amazon-cloudwatch-agent
systemctl start amazon-cloudwatch-agent

# Signal the completion of the installation
echo "Wazuh installation completed successfully!"
/opt/aws/bin/cfn-signal -e 0 --stack ${project_name} --resource WazuhAutoScalingGroup --region $(curl -s 169.254.169.254/latest/dynamic/instance-identity/document | jq -r .region)