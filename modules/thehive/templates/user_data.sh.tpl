#!/bin/bash
# File: modules/thehive/templates/user_data.sh.tpl

# Exit immediately if a command exits with a non-zero status
set -e

# Log all output
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

echo "Starting TheHive installation process..."

# Update system
apt-get update
apt-get upgrade -y
apt-get install -y curl wget unzip git apt-transport-https ca-certificates software-properties-common gnupg-agent jq python3 python3-pip openjdk-11-jre-headless

# Install AWS CLI
pip3 install --upgrade awscli

# Set hostname
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
hostnamectl set-hostname thehive-$INSTANCE_ID

# Install Docker
echo "Installing Docker..."
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io
systemctl enable docker
systemctl start docker

# Install Docker Compose
echo "Installing Docker Compose..."
curl -L "https://github.com/docker/compose/releases/download/v2.21.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Create TheHive user
echo "Creating TheHive user..."
useradd -m -s /bin/bash thehive
usermod -aG docker thehive

# Create TheHive directories
echo "Creating TheHive directories..."
mkdir -p /opt/thehive/data
mkdir -p /opt/thehive/config
mkdir -p /opt/thehive/logs
chown -R thehive:thehive /opt/thehive

# Create Docker Compose file
echo "Creating Docker Compose file..."
cat > /opt/thehive/docker-compose.yml << EOF
version: '3'

services:
  elasticsearch:
    image: 'elasticsearch:7.17.7'
    container_name: elasticsearch
    restart: unless-stopped
    ports:
      - '127.0.0.1:9200:9200'
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms2g -Xmx2g"
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data
    ulimits:
      nofile:
        soft: 65536
        hard: 65536

  thehive:
    image: 'thehiveproject/thehive4:${thehive_version}'
    container_name: thehive
    restart: unless-stopped
    depends_on:
      - elasticsearch
      - cassandra
    ports:
      - '9000:9000'
    volumes:
      - /opt/thehive/config/application.conf:/etc/thehive/application.conf
      - /opt/thehive/data:/data
      - /opt/thehive/logs:/var/log/thehive
    environment:
      - TZ=UTC

  cassandra:
    image: 'cassandra:4.0'
    container_name: cassandra
    restart: unless-stopped
    ports:
      - '127.0.0.1:9042:9042'
    environment:
      - MAX_HEAP_SIZE=1G
      - HEAP_NEWSIZE=1G
      - CASSANDRA_CLUSTER_NAME=thehive
    volumes:
      - cassandra_data:/var/lib/cassandra
    ulimits:
      memlock: -1
      nproc: 32768
      nofile: 100000

volumes:
  elasticsearch_data:
  cassandra_data:
EOF

# Create TheHive configuration
echo "Creating TheHive configuration..."
cat > /opt/thehive/config/application.conf << EOF
play.http.secret.key="${admin_password}"

# JanusGraph
db {
  provider: janusgraph
  janusgraph {
    storage {
      backend: cql
      hostname: ["cassandra"]

      cql {
        cluster-name: thehive
        keyspace: thehive
      }
    }
  }
}

storage {
  provider: localfs
  localfs.location: /data
}

play.modules.enabled += org.thp.thehive.connector.cortex.CortexModule
cortex {
  servers = [
    {
      name = "Cortex"
      url = "${cortex_url}"
      auth {
        type = "bearer"
        key = "${cortex_api_key}"
      }
    }
  ]
}

play.modules.enabled += org.thp.thehive.connector.misp.MispModule
misp {
  interval: 5 min
  servers: [
    {
      name = "MISP"
      url = "https://misp.${var.dns_domain}"
      auth {
        type = "key"
        key = "CHANGEME"
      }
      wsConfig {
        proxy {
          host: ""
          port: 0
        }
      }
      tags = ["misp"]
      caseTemplate = "misp-template"
      includeTags = ["includeme"]
      excludeTags = ["excludeme"]
    }
  ]
}

# Authentication
auth {
  # "provider" parameter contains the authentication provider(s).
  # Default is local authentication provider.
  providers = [
    {
      name: local
      # User management endpoint
      #userSynchronizer {
      #  # Interval between synchronization in minutes
      #  interval: 1 hour
      #  # URL of the user management endpoint
      #  url: "https://my-user-management-endpoint.example"
      #  # Authentication type (none, basic, bearer)
      #  auth {
      #    type: bearer
      #    key: "API key"
      #  }
      #  # Request entity format
      #  wsConfig {
      #   ws.useragent: "TheHive"
      #    ws.followRedirects: true
      #    ws.timeout: 1 minute
      #    #ws.ssl.loose.acceptAnyCertificate: true
      #  }
      #}
    }
  ]

  # Default authentication provider
  defaultProvider: local
}

# Maximum time between two requests without asking authentication
session {
  warning: 5m
  inactivity: 1h
}

# REST API configuration
play.http.parser.maxDiskBuffer: 1GB

# Max file size (default: 100MB)
play.http.parser.maxMemoryBuffer: 100MB

# Organization configuration
# Organization is disabled by default.
#
# If you do not want to use organization setting,
# keep this section commented out.
#
# If you want to use organization setting, uncomment
# following lines.
#
# warning: if you want to use organization, make sure
# that all user providers are organization aware.
# We recommend using SSO provider (OAuth 2 or SAML).
#
organization {
  enabled = false

  # Time to live of the cases
  # When a case is older that organization.ttl it is deleted
  # This setting must be defined when organizations are enabled
  #ttl = 3650 days
}

# S3 storage configuration
# s3 {
#   endpoint = "s3.amazonaws.com"
#   region = "${aws_region}"
#   bucket = "${var.project_name}-thehive-data"
#   usePathAccessStyle = false
#   accessKey = "ACCESS_KEY"
#   secretKey = "SECRET_KEY"
# }

notification.webhook.endpoints = [
  {
    name: n8n-webhook
    url: "https://n8n.${var.dns_domain}/webhook/thehive"
    version: 0
    auth: {type:"none"}
    wsConfig: {}
    includedTheHiveOrganizations: ["*"]
    excludedTheHiveOrganizations: []
  }
]
EOF

# Start TheHive
echo "Starting TheHive..."
cd /opt/thehive
docker-compose up -d

# Wait for TheHive to be up
echo "Waiting for TheHive to be available..."
until $(curl --output /dev/null --silent --head --fail http://localhost:9000); do
  printf '.'
  sleep 10
done

# Create initial admin user
echo "Creating admin user..."
sleep 30  # Give a bit more time for the services to fully initialize

# Using Docker to run the API call to create the admin user
docker run --network host --rm curlimages/curl:7.84.0 \
  -X POST http://localhost:9000/api/user \
  -H 'Content-Type: application/json' \
  -d '{
    "login": "admin",
    "name": "Administrator",
    "password": "'"${admin_password}"'",
    "profile": "admin",
    "email": "admin@example.com"
  }'

# Store API key in Parameter Store
echo "Creating API key for automation..."
API_KEY=$(docker run --network host --rm curlimages/curl:7.84.0 \
  -X POST http://localhost:9000/api/user/admin/key/renew \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Basic '$(echo -n "admin:${admin_password}" | base64) \
  | jq -r '.key')

# Store the API key in SSM Parameter Store
if [ ! -z "$API_KEY" ]; then
  aws ssm put-parameter \
    --name "/${project_name}/thehive/api_key" \
    --type "SecureString" \
    --value "$API_KEY" \
    --overwrite \
    --region $(curl -s 169.254.169.254/latest/dynamic/instance-identity/document | jq -r .region)
else
  echo "Failed to retrieve API key"
fi

# Create case templates
echo "Creating case templates..."

# SOC Investigation template
docker run --network host --rm curlimages/curl:7.84.0 \
  -X POST http://localhost:9000/api/case/template \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${API_KEY}" \
  -d '{
    "name": "SOC Investigation",
    "titlePrefix": "SOC",
    "description": "Template for SOC security investigations",
    "severity": 2,
    "tlp": 2,
    "tasks": [
      {"title": "Initial Assessment", "description": "Review the alert and determine if it requires investigation"},
      {"title": "Evidence Collection", "description": "Collect logs, network traffic, and system information"},
      {"title": "Threat Analysis", "description": "Analyze collected data for indicators of compromise"},
      {"title": "Impact Assessment", "description": "Determine the scope and impact of the incident"},
      {"title": "Containment", "description": "Implement containment measures if necessary"},
      {"title": "Remediation", "description": "Implement remediation steps to resolve the incident"},
      {"title": "Documentation", "description": "Document findings and actions taken"}
    ],
    "customFields": [
      {"name": "detection_source", "reference": "detection_source", "type": "string", "options": ["IDS", "EDR", "SIEM", "Threat Intel", "User Report", "Other"]},
      {"name": "attack_vector", "reference": "attack_vector", "type": "string", "options": ["Email", "Web", "USB", "Network", "Unknown"]},
      {"name": "affected_systems", "reference": "affected_systems", "type": "string", "mandatory": false},
      {"name": "malware_identified", "reference": "malware_identified", "type": "boolean", "mandatory": false}
    ]
  }'

# MISP Alert template
docker run --network host --rm curlimages/curl:7.84.0 \
  -X POST http://localhost:9000/api/case/template \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${API_KEY}" \
  -d '{
    "name": "MISP Alert",
    "titlePrefix": "MISP",
    "description": "Template for alerts imported from MISP",
    "severity": 2,
    "tlp": 2,
    "tasks": [
      {"title": "Validate IOCs", "description": "Verify the indicators of compromise are accurate and relevant"},
      {"title": "Search Environment", "description": "Search for IOCs in your environment"},
      {"title": "Report Findings", "description": "Document if IOCs were found and any further actions taken"}
    ],
    "customFields": [
      {"name": "misp_event_id", "reference": "misp_event_id", "type": "string", "mandatory": true},
      {"name": "threat_level", "reference": "threat_level", "type": "string", "options": ["High", "Medium", "Low", "Undefined"]},
      {"name": "analysis_level", "reference": "analysis_level", "type": "string", "options": ["Initial", "Ongoing", "Complete"]},
      {"name": "ioc_count", "reference": "ioc_count", "type": "integer", "mandatory": false}
    ]
  }'

# Malware Analysis template
docker run --network host --rm curlimages/curl:7.84.0 \
  -X POST http://localhost:9000/api/case/template \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${API_KEY}" \
  -d '{
    "name": "Malware Analysis",
    "titlePrefix": "MAL",
    "description": "Template for malware analysis investigations",
    "severity": 2,
    "tlp": 2,
    "tasks": [
      {"title": "Static Analysis", "description": "Perform static analysis of the malware sample"},
      {"title": "Dynamic Analysis", "description": "Execute the malware in a safe environment and observe behavior"},
      {"title": "Network Analysis", "description": "Analyze network communications made by the malware"},
      {"title": "IOC Extraction", "description": "Extract indicators of compromise from the malware"},
      {"title": "Report Creation", "description": "Create a detailed malware analysis report"}
    ],
    "customFields": [
      {"name": "malware_type", "reference": "malware_type", "type": "string", "options": ["Ransomware", "Trojan", "RAT", "Worm", "Rootkit", "Botnet", "Other"]},
      {"name": "malware_family", "reference": "malware_family", "type": "string", "mandatory": false},
      {"name": "sample_hash", "reference": "sample_hash", "type": "string", "mandatory": true},
      {"name": "sandbox_used", "reference": "sandbox_used", "type": "string", "options": ["Cuckoo", "ANY.RUN", "Joe Sandbox", "VMRay", "Other"], "mandatory": false}
    ]
  }'

# Configure AWS CloudWatch agent
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
            "file_path": "/var/log/user-data.log",
            "log_group_name": "/thehive/user-data",
            "log_stream_name": "{instance_id}",
            "timezone": "UTC"
          },
          {
            "file_path": "/opt/thehive/logs/*.log",
            "log_group_name": "/thehive/application",
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
echo "TheHive installation completed successfully!"
/opt/aws/bin/cfn-signal -e 0 --stack ${project_name} --resource TheHiveAutoScalingGroup --region $(curl -s 169.254.169.254/latest/dynamic/instance-identity/document | jq -r .region)