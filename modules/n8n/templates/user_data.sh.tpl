#!/bin/bash
# File: modules/n8n/templates/user_data.sh.tpl

# Exit immediately if a command exits with a non-zero status
set -e

# Log all output
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

echo "Starting n8n installation process..."

# Update system
apt-get update
apt-get upgrade -y
apt-get install -y curl wget unzip git apt-transport-https ca-certificates software-properties-common gnupg-agent jq python3 python3-pip

# Install AWS CLI
pip3 install --upgrade awscli

# Set hostname
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
hostnamectl set-hostname n8n-$INSTANCE_ID

# Install Node.js
echo "Installing Node.js..."
curl -sL https://deb.nodesource.com/setup_16.x | bash -
apt-get install -y nodejs

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

# Create n8n user
echo "Creating n8n user..."
useradd -m -s /bin/bash n8n
usermod -aG docker n8n

# Create n8n directories
echo "Creating n8n directories..."
mkdir -p /opt/n8n/data
mkdir -p /opt/n8n/config
mkdir -p /opt/n8n/workflows
mkdir -p /opt/n8n/scripts
mkdir -p /opt/n8n/credentials
chown -R n8n:n8n /opt/n8n

# Create Docker Compose file
echo "Creating Docker Compose file..."
cat > /opt/n8n/docker-compose.yml << EOF
version: '3'

services:
  n8n:
    image: n8nio/n8n:${n8n_version}
    restart: always
    ports:
      - "5678:5678"
    environment:
      - DB_TYPE=postgresdb
      - DB_POSTGRESDB_HOST=${db_endpoint}
      - DB_POSTGRESDB_PORT=5432
      - DB_POSTGRESDB_DATABASE=${db_name}
      - DB_POSTGRESDB_USER=${db_user}
      - DB_POSTGRESDB_PASSWORD=${db_password}
      - N8N_PROTOCOL=https
      - N8N_PORT=5678
      - NODE_ENV=production
      - N8N_ENCRYPTION_KEY=${encryption_key}
      - WEBHOOK_URL=${webhook_url}
      - N8N_DISABLE_PRODUCTION_WARNING=true
      - N8N_METRICS=true
      - EXECUTIONS_DATA_SAVE_ON_ERROR=all
      - EXECUTIONS_DATA_SAVE_ON_SUCCESS=all
      - EXECUTIONS_DATA_SAVE_ON_PROGRESS=true
      - EXECUTIONS_DATA_SAVE_MANUAL_EXECUTIONS=true
      - EXECUTIONS_DATA_PRUNE=true
      - EXECUTIONS_DATA_MAX_AGE=336
      - EXECUTIONS_MODE=queue
      - QUEUE_BULL_REDIS_HOST=redis
      - QUEUE_BULL_REDIS_PORT=6379
      - GENERIC_TIMEZONE=UTC
      - TZ=UTC
      - N8N_EMAIL_MODE=smtp
      - N8N_SMTP_HOST=smtp.example.com
      - N8N_SMTP_PORT=587
      - N8N_SMTP_USER=user
      - N8N_SMTP_PASS=password
      - N8N_SMTP_SSL=false
      - N8N_SMTP_FROM=n8n@example.com
    volumes:
      - /opt/n8n/data:/home/node/.n8n
      - /opt/n8n/workflows:/opt/n8n/workflows
      - /opt/n8n/credentials:/opt/n8n/credentials
    depends_on:
      - redis

  redis:
    image: redis:7-alpine
    restart: always
    command: redis-server --requirepass redis
    volumes:
      - redis-data:/data

volumes:
  redis-data:
EOF

# Create SOC integration workflows
echo "Creating SOC integration workflows..."

# Create n8n directory for workflows
mkdir -p /opt/n8n/data/workflows

# Create Wazuh alert workflow
cat > /opt/n8n/data/workflows/wazuh-alerts.json << EOF
{
  "name": "Wazuh Alerts Processing",
  "nodes": [
    {
      "parameters": {
        "httpMethod": "POST",
        "path": "wazuh-alerts",
        "options": {}
      },
      "name": "Webhook",
      "type": "n8n-nodes-base.webhook",
      "typeVersion": 1,
      "position": [
        250,
        300
      ]
    },
    {
      "parameters": {
        "conditions": {
          "boolean": [
            {
              "value1": "={{ \$json.rule.level >= 10 }}",
              "value2": true
            }
          ]
        }
      },
      "name": "High Severity",
      "type": "n8n-nodes-base.if",
      "typeVersion": 1,
      "position": [
        470,
        300
      ]
    },
    {
      "parameters": {
        "url": "${thehive_endpoint}/api/alert",
        "options": {
          "headers": {
            "Content-Type": "application/json",
            "Authorization": "Bearer YOUR_THEHIVE_API_KEY"
          }
        },
        "sendBody": true,
        "bodyParameters": {
          "parameters": [
            {
              "name": "title",
              "value": "={{ \"WAZUH Alert: \" + \$json.rule.description }}"
            },
            {
              "name": "description",
              "value": "={{ \$json.rule.description + \"\\n\\nAgent: \" + \$json.agent.name + \" (\" + \$json.agent.id + \")\\n\\nRule ID: \" + \$json.rule.id + \"\\nLevel: \" + \$json.rule.level + \"\\n\\nFull log: \" + \$json.full_log }}"
            },
            {
              "name": "type",
              "value": "wazuh_alert"
            },
            {
              "name": "source",
              "value": "={{ \$json.agent.name }}"
            },
            {
              "name": "sourceRef",
              "value": "={{ \$json.agent.id + \"-\" + \$json.rule.id }}"
            },
            {
              "name": "severity",
              "value": 3
            },
            {
              "name": "tags",
              "value": "={{ [\$json.rule.groups] }}"
            }
          ]
        }
      },
      "name": "Create TheHive Alert",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 1,
      "position": [
        660,
        240
      ]
    },
    {
      "parameters": {
        "url": "https://hooks.slack.com/services/YOUR_SLACK_WEBHOOK",
        "options": {
          "headers": {
            "Content-Type": "application/json"
          }
        },
        "sendBody": true,
        "bodyParameters": {
          "parameters": [
            {
              "name": "text",
              "value": "={{ \"⚠️ *WAZUH HIGH SEVERITY ALERT* ⚠️\\n\\n*Rule:* \" + \$json.rule.description + \"\\n*Level:* \" + \$json.rule.level + \"\\n*Agent:* \" + \$json.agent.name + \"\\n*IP:* \" + \$json.agent.ip + \"\\n\\n*Details:* \" + \$json.full_log }}"
            }
          ]
        }
      },
      "name": "Send to Slack",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 1,
      "position": [
        660,
        400
      ]
    },
    {
      "parameters": {
        "functionCode": "// Record metrics for all alerts\nconst severity = $input.item.json.rule.level;\nlet severityCategory;\n\nif (severity >= 12) {\n  severityCategory = 'critical';\n} else if (severity >= 8) {\n  severityCategory = 'high';\n} else if (severity >= 5) {\n  severityCategory = 'medium';\n} else {\n  severityCategory = 'low';\n}\n\n// Group the alerts by rule ID\nconst ruleId = $input.item.json.rule.id;\nconst ruleDescription = $input.item.json.rule.description;\nconst agentName = $input.item.json.agent.name;\n\nreturn {\n  alertTimestamp: $input.item.json.timestamp,\n  severity: severity,\n  severityCategory: severityCategory,\n  ruleId: ruleId,\n  ruleDescription: ruleDescription,\n  agentName: agentName,\n  groupName: $input.item.json.rule.groups\n};"
      },
      "name": "Process Alert Data",
      "type": "n8n-nodes-base.function",
      "typeVersion": 1,
      "position": [
        470,
        480
      ]
    },
    {
      "parameters": {
        "url": "http://localhost:9200/wazuh-alerts-stats/_doc",
        "options": {
          "headers": {
            "Content-Type": "application/json"
          }
        },
        "sendBody": true,
        "bodyParameters": {
          "parameters": [
            {
              "name": "",
              "value": "={{ $json }}"
            }
          ]
        }
      },
      "name": "Store Analytics",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 1,
      "position": [
        660,
        560
      ]
    }
  ],
  "connections": {
    "Webhook": {
      "main": [
        [
          {
            "node": "High Severity",
            "type": "main",
            "index": 0
          },
          {
            "node": "Process Alert Data",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "High Severity": {
      "main": [
        [
          {
            "node": "Create TheHive Alert",
            "type": "main",
            "index": 0
          },
          {
            "node": "Send to Slack",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Process Alert Data": {
      "main": [
        [
          {
            "node": "Store Analytics",
            "type": "main",
            "index": 0
          }
        ]
      ]
    }
  },
  "active": true,
  "settings": {}
}
EOF

# Create MISP to TheHive workflow
cat > /opt/n8n/data/workflows/misp-thehive.json << EOF
{
  "name": "MISP to TheHive Integration",
  "nodes": [
    {
      "parameters": {
        "triggerTimes": {
          "item": [
            {
              "hour": 9,
              "minute": 0
            }
          ]
        }
      },
      "name": "Daily Sync",
      "type": "n8n-nodes-base.cron",
      "typeVersion": 1,
      "position": [
        250,
        300
      ]
    },
    {
      "parameters": {
        "url": "${misp_endpoint}/events/restSearch",
        "options": {
          "headers": {
            "Authorization": "YOUR_MISP_API_KEY",
            "Content-Type": "application/json",
            "Accept": "application/json"
          }
        },
        "sendBody": true,
        "bodyParameters": {
          "parameters": [
            {
              "name": "limit",
              "value": "50"
            },
            {
              "name": "published",
              "value": "1"
            },
            {
              "name": "timestamp",
              "value": "1d"
            }
          ]
        }
      },
      "name": "Get MISP Events",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 1,
      "position": [
        450,
        300
      ]
    },
    {
      "parameters": {
        "operation": "transformInput",
        "sourcePath": "response.Event",
        "destinationPath": "data"
      },
      "name": "Extract Events",
      "type": "n8n-nodes-base.set",
      "typeVersion": 1,
      "position": [
        650,
        300
      ]
    },
    {
      "parameters": {},
      "name": "Process Each Event",
      "type": "n8n-nodes-base.splitInBatches",
      "typeVersion": 1,
      "position": [
        820,
        300
      ]
    },
    {
      "parameters": {
        "functionCode": "// Transform MISP event to TheHive alert format\nconst event = $input.item.json;\n\n// Construct IOCs\nconst artifacts = [];\nif (event.Attribute) {\n  for (const attr of event.Attribute) {\n    let dataType;\n    \n    switch (attr.type) {\n      case 'ip-src':\n      case 'ip-dst':\n        dataType = 'ip';\n        break;\n      case 'domain':\n      case 'hostname':\n        dataType = 'domain';\n        break;\n      case 'url':\n        dataType = 'url';\n        break;\n      case 'md5':\n      case 'sha1':\n      case 'sha256':\n        dataType = 'hash';\n        break;\n      case 'email-src':\n      case 'email-dst':\n        dataType = 'mail';\n        break;\n      default:\n        dataType = 'other';\n    }\n    \n    artifacts.push({\n      dataType: dataType,\n      data: attr.value,\n      message: attr.comment || ''\n    });\n  }\n}\n\nreturn {\n  title: `MISP: ${event.info}`,\n  description: `MISP Event #${event.id}\\n\\n${event.info}\\n\\nTags: ${event.Tag.map(t => t.name).join(', ')}`,\n  type: 'misp-event',\n  source: 'MISP',\n  sourceRef: `MISP-${event.id}`,\n  artifacts: artifacts,\n  severity: 2,\n  tags: event.Tag.map(t => t.name),\n  tlp: 2,\n  status: 'New',\n  date: new Date().getTime()\n};"
      },
      "name": "Format TheHive Alert",
      "type": "n8n-nodes-base.function",
      "typeVersion": 1,
      "position": [
        990,
        300
      ]
    },
    {
      "parameters": {
        "url": "${thehive_endpoint}/api/alert",
        "options": {
          "headers": {
            "Content-Type": "application/json",
            "Authorization": "Bearer YOUR_THEHIVE_API_KEY"
          }
        },
        "sendBody": true,
        "bodyParameters": {
          "parameters": [
            {
              "name": "",
              "value": "={{ $json }}"
            }
          ]
        }
      },
      "name": "Create TheHive Alert",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 1,
      "position": [
        1160,
        300
      ]
    },
    {
      "parameters": {
        "conditions": {
          "boolean": [
            {
              "value1": "={{ $json.statusCode >= 400 }}",
              "value2": true
            }
          ]
        }
      },
      "name": "Error?",
      "type": "n8n-nodes-base.if",
      "typeVersion": 1,
      "position": [
        1330,
        300
      ]
    },
    {
      "parameters": {
        "url": "https://hooks.slack.com/services/YOUR_SLACK_WEBHOOK",
        "options": {
          "headers": {
            "Content-Type": "application/json"
          }
        },
        "sendBody": true,
        "bodyParameters": {
          "parameters": [
            {
              "name": "text",
              "value": "={{ \"❌ Error importing MISP event to TheHive:\\n\\n\" + $json.statusMessage }}"
            }
          ]
        }
      },
      "name": "Report Error",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 1,
      "position": [
        1510,
        220
      ]
    }
  ],
  "connections": {
    "Daily Sync": {
      "main": [
        [
          {
            "node": "Get MISP Events",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Get MISP Events": {
      "main": [
        [
          {
            "node": "Extract Events",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Extract Events": {
      "main": [
        [
          {
            "node": "Process Each Event",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Process Each Event": {
      "main": [
        [
          {
            "node": "Format TheHive Alert",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Format TheHive Alert": {
      "main": [
        [
          {
            "node": "Create TheHive Alert",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Create TheHive Alert": {
      "main": [
        [
          {
            "node": "Error?",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Error?": {
      "main": [
        [
          {
            "node": "Report Error",
            "type": "main",
            "index": 0
          }
        ]
      ]
    }
  },
  "active": true,
  "settings": {}
}
EOF

# Create SOC Health Check workflow
cat > /opt/n8n/data/workflows/soc-healthcheck.json << EOF
{
  "name": "SOC Infrastructure Health Check",
  "nodes": [
    {
      "parameters": {
        "triggerTimes": {
          "item": [
            {
              "hour": 8,
              "minute": 0
            },
            {
              "hour": 12,
              "minute": 0
            },
            {
              "hour": 16,
              "minute": 0
            },
            {
              "hour": 20,
              "minute": 0
            }
          ]
        }
      },
      "name": "Schedule",
      "type": "n8n-nodes-base.cron",
      "typeVersion": 1,
      "position": [
        250,
        300
      ]
    },
    {
      "parameters": {
        "url": "${wazuh_endpoint}/",
        "options": {
          "headers": {
            "Authorization": "Bearer YOUR_WAZUH_API_KEY"
          }
        }
      },
      "name": "Check Wazuh",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 1,
      "position": [
        460,
        200
      ]
    },
    {
      "parameters": {
        "url": "${thehive_endpoint}/api/alert",
        "options": {
          "headers": {
            "Authorization": "Bearer YOUR_THEHIVE_API_KEY"
          }
        }
      },
      "name": "Check TheHive",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 1,
      "position": [
        460,
        360
      ]
    },
    {
      "parameters": {
        "url": "${misp_endpoint}/servers/getSettings",
        "options": {
          "headers": {
            "Authorization": "YOUR_MISP_API_KEY",
            "Accept": "application/json"
          }
        }
      },
      "name": "Check MISP",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 1,
      "position": [
        460,
        520
      ]
    },
    {
      "parameters": {
        "functionCode": "// Collect health status of all SOC components\nconst results = [];\nconst items = $input.all;\n\nconst wazuhResult = items[0];\nconst thehiveResult = items[1];\nconst mispResult = items[2];\n\n// Check Wazuh status\nlet wazuhStatus = 'DOWN';\nlet wazuhError = 'Unknown error';\ntry {\n  if (wazuhResult[0].json.statusCode < 400) {\n    wazuhStatus = 'UP';\n    wazuhError = '';\n  } else {\n    wazuhError = wazuhResult[0].json.statusMessage || 'API returned error status';\n  }\n} catch (e) {\n  wazuhError = e.message;\n}\n\n// Check TheHive status\nlet thehiveStatus = 'DOWN';\nlet thehiveError = 'Unknown error';\ntry {\n  if (thehiveResult[0].json.statusCode < 400) {\n    thehiveStatus = 'UP';\n    thehiveError = '';\n  } else {\n    thehiveError = thehiveResult[0].json.statusMessage || 'API returned error status';\n  }\n} catch (e) {\n  thehiveError = e.message;\n}\n\n// Check MISP status\nlet mispStatus = 'DOWN';\nlet mispError = 'Unknown error';\ntry {\n  if (mispResult[0].json.statusCode < 400) {\n    mispStatus = 'UP';\n    mispError = '';\n  } else {\n    mispError = mispResult[0].json.statusMessage || 'API returned error status';\n  }\n} catch (e) {\n  mispError = e.message;\n}\n\n// Calculate overall health\nconst allUp = wazuhStatus === 'UP' && thehiveStatus === 'UP' && mispStatus === 'UP';\nconst overallStatus = allUp ? 'HEALTHY' : 'DEGRADED';\n\n// Format report\nreturn {\n  timestamp: new Date().toISOString(),\n  overall: overallStatus,\n  components: {\n    wazuh: {\n      status: wazuhStatus,\n      error: wazuhError\n    },\n    thehive: {\n      status: thehiveStatus,\n      error: thehiveError\n    },\n    misp: {\n      status: mispStatus,\n      error: mispError\n    }\n  }\n};"
      },
      "name": "Compile Health Report",
      "type": "n8n-nodes-base.function",
      "typeVersion": 1,
      "position": [
        700,
        300
      ]
    },
    {
      "parameters": {
        "url": "https://hooks.slack.com/services/YOUR_SLACK_WEBHOOK",
        "options": {
          "headers": {
            "Content-Type": "application/json"
          }
        },
        "sendBody": true,
        "bodyParameters": {
          "parameters": [
            {
              "name": "text",
              "value": "={{ \"SOC Health Check - \" + $json.timestamp + \"\\n\\nOverall: \" + ($json.overall === \"HEALTHY\" ? \"✅ HEALTHY\" : \"❌ DEGRADED\") + \"\\n\\nComponents:\\n\\nWazuh: \" + ($json.components.wazuh.status === \"UP\" ? \"✅ UP\" : \"❌ DOWN\") + ($json.components.wazuh.error ? \" (\" + $json.components.wazuh.error + \")\" : \"\") + \"\\n\\nTheHive: \" + ($json.components.thehive.status === \"UP\" ? \"✅ UP\" : \"❌ DOWN\") + ($json.components.thehive.error ? \" (\" + $json.components.thehive.error + \")\" : \"\") + \"\\n\\nMISP: \" + ($json.components.misp.status === \"UP\" ? \"✅ UP\" : \"❌ DOWN\") + ($json.components.misp.error ? \" (\" + $json.components.misp.error + \")\" : \"\") }}"
            }
          ]
        }
      },
      "name": "Send Report to Slack",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 1,
      "position": [
        880,
        300
      ]
    }
  ],
  "connections": {
    "Schedule": {
      "main": [
        [
          {
            "node": "Check Wazuh",
            "type": "main",
            "index": 0
          },
          {
            "node": "Check TheHive",
            "type": "main",
            "index": 0
          },
          {
            "node": "Check MISP",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Check Wazuh": {
      "main": [
        [
          {
            "node": "Compile Health Report",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Check TheHive": {
      "main": [
        [
          {
            "node": "Compile Health Report",
            "type": "main",
            "index": 1
          }
        ]
      ]
    },
    "Check MISP": {
      "main": [
        [
          {
            "node": "Compile Health Report",
            "type": "main",
            "index": 2
          }
        ]
      ]
    },
    "Compile Health Report": {
      "main": [
        [
          {
            "node": "Send Report to Slack",
            "type": "main",
            "index": 0
          }
        ]
      ]
    }
  },
  "active": true,
  "settings": {}
}
EOF

# Setup systemd service for n8n
echo "Setting up systemd service..."
cat > /etc/systemd/system/n8n.service << EOF
[Unit]
Description=n8n workflow automation
After=network.target docker.service
Requires=docker.service

[Service]
User=n8n
Group=n8n
WorkingDirectory=/opt/n8n
ExecStart=/usr/local/bin/docker-compose up
ExecStop=/usr/local/bin/docker-compose down
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=n8n

[Install]
WantedBy=multi-user.target
EOF

# Add script to update API keys
cat > /opt/n8n/scripts/update-api-keys.sh << EOF
#!/bin/bash

# Script to update API keys in n8n workflows

# Wazuh API key
WAZUH_API_KEY=\$1

# TheHive API key
THEHIVE_API_KEY=\$2

# MISP API key
MISP_API_KEY=\$3

# Slack webhook URL
SLACK_WEBHOOK=\$4

if [ -z "\$WAZUH_API_KEY" ] || [ -z "\$THEHIVE_API_KEY" ] || [ -z "\$MISP_API_KEY" ] || [ -z "\$SLACK_WEBHOOK" ]; then
  echo "Usage: \$0 <wazuh_api_key> <thehive_api_key> <misp_api_key> <slack_webhook>"
  exit 1
fi

# Update Wazuh alerts workflow
sed -i "s#YOUR_THEHIVE_API_KEY#\$THEHIVE_API_KEY#g" /opt/n8n/data/workflows/wazuh-alerts.json
sed -i "s#YOUR_SLACK_WEBHOOK#\$SLACK_WEBHOOK#g" /opt/n8n/data/workflows/wazuh-alerts.json

# Update MISP to TheHive workflow
sed -i "s#YOUR_MISP_API_KEY#\$MISP_API_KEY#g" /opt/n8n/data/workflows/misp-thehive.json
sed -i "s#YOUR_THEHIVE_API_KEY#\$THEHIVE_API_KEY#g" /opt/n8n/data/workflows/misp-thehive.json
sed -i "s#YOUR_SLACK_WEBHOOK#\$SLACK_WEBHOOK#g" /opt/n8n/data/workflows/misp-thehive.json

# Update SOC health check workflow
sed -i "s#YOUR_WAZUH_API_KEY#\$WAZUH_API_KEY#g" /opt/n8n/data/workflows/soc-healthcheck.json
sed -i "s#YOUR_THEHIVE_API_KEY#\$THEHIVE_API_KEY#g" /opt/n8n/data/workflows/soc-healthcheck.json
sed -i "s#YOUR_MISP_API_KEY#\$MISP_API_KEY#g" /opt/n8n/data/workflows/soc-healthcheck.json
sed -i "s#YOUR_SLACK_WEBHOOK#\$SLACK_WEBHOOK#g" /opt/n8n/data/workflows/soc-healthcheck.json

echo "API keys updated successfully!"
EOF

chmod +x /opt/n8n/scripts/update-api-keys.sh
chown n8n:n8n /opt/n8n/scripts/update-api-keys.sh

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
            "log_group_name": "/n8n/user-data",
            "log_stream_name": "{instance_id}",
            "timezone": "UTC"
          },
          {
            "file_path": "/opt/n8n/logs/n8n.log",
            "log_group_name": "/n8n/application",
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

# Start services
echo "Starting services..."
systemctl enable amazon-cloudwatch-agent
systemctl start amazon-cloudwatch-agent
systemctl enable n8n
systemctl start n8n

# Signal the completion of the installation
echo "n8n installation completed successfully!"
/opt/aws/bin/cfn-signal -e 0 --stack ${project_name} --resource N8nAutoScalingGroup --region $(curl -s 169.254.169.254/latest/dynamic/instance-identity/document | jq -r .region)