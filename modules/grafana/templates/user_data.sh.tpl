#!/bin/bash
# File: modules/grafana/templates/user_data.sh.tpl

# Exit immediately if a command exits with a non-zero status
set -e

# Log all output
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

echo "Starting Grafana installation process..."

# Update system
apt-get update
apt-get upgrade -y
apt-get install -y curl wget gnupg apt-transport-https ca-certificates software-properties-common python3 python3-pip

# Install AWS CLI
pip3 install --upgrade awscli

# Set hostname
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
hostnamectl set-hostname grafana-$INSTANCE_ID

# Install Grafana
echo "Installing Grafana..."
wget -q -O /usr/share/keyrings/grafana.key https://apt.grafana.com/gpg.key
echo "deb [signed-by=/usr/share/keyrings/grafana.key] https://apt.grafana.com stable main" | tee -a /etc/apt/sources.list.d/grafana.list
apt-get update
apt-get install -y grafana=${grafana_version}

# Configure Grafana
echo "Configuring Grafana..."
mkdir -p /etc/grafana/provisioning/datasources
mkdir -p /etc/grafana/provisioning/dashboards
mkdir -p /var/lib/grafana/dashboards

# Grafana main configuration
cat > /etc/grafana/grafana.ini << EOF
[server]
domain = grafana.${dns_domain}
root_url = https://grafana.${dns_domain}

[security]
admin_user = admin
admin_password = ${admin_password}
disable_gravatar = true

[auth.anonymous]
enabled = false

[smtp]
enabled = true
host = smtp.example.com:587
user = grafana@example.com
password = example_password
from_address = grafana@example.com
from_name = Grafana SOC

[dashboards]
default_home_dashboard_path = /var/lib/grafana/dashboards/soc-overview.json
EOF

# Configure CloudWatch data source
cat > /etc/grafana/provisioning/datasources/aws-cloudwatch.yaml << EOF
apiVersion: 1

datasources:
  - name: CloudWatch
    type: cloudwatch
    jsonData:
      authType: default
      defaultRegion: ${cloudwatch_region}
    version: 1
    editable: true
EOF

# Configure Elasticsearch data source
cat > /etc/grafana/provisioning/datasources/elasticsearch.yaml << EOF
apiVersion: 1

datasources:
  - name: Elasticsearch
    type: elasticsearch
    url: ${elasticsearch_endpoint}
    database: wazuh-*
    jsonData:
      esVersion: 7.10.0
      timeField: '@timestamp'
      interval: Daily
    secureJsonData:
      password: admin
    user: admin
    version: 1
    editable: true
EOF

# Configure dashboard provider
cat > /etc/grafana/provisioning/dashboards/default.yaml << EOF
apiVersion: 1

providers:
  - name: 'Default'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    options:
      path: /var/lib/grafana/dashboards
EOF

# Create SOC Overview Dashboard
cat > /var/lib/grafana/dashboards/soc-overview.json << EOF
{
  "annotations": {
    "list": [
      {
        "builtIn": 1,
        "datasource": "-- Grafana --",
        "enable": true,
        "hide": true,
        "iconColor": "rgba(0, 211, 255, 1)",
        "name": "Annotations & Alerts",
        "type": "dashboard"
      }
    ]
  },
  "editable": true,
  "gnetId": null,
  "graphTooltip": 0,
  "id": 1,
  "links": [],
  "panels": [
    {
      "aliasColors": {},
      "bars": false,
      "dashLength": 10,
      "dashes": false,
      "datasource": "CloudWatch",
      "fieldConfig": {
        "defaults": {},
        "overrides": []
      },
      "fill": 1,
      "fillGradient": 0,
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 0,
        "y": 0
      },
      "hiddenSeries": false,
      "id": 2,
      "legend": {
        "avg": false,
        "current": false,
        "max": false,
        "min": false,
        "show": true,
        "total": false,
        "values": false
      },
      "lines": true,
      "linewidth": 1,
      "nullPointMode": "null",
      "options": {
        "alertThreshold": true
      },
      "percentage": false,
      "pluginVersion": "7.5.5",
      "pointradius": 2,
      "points": false,
      "renderer": "flot",
      "seriesOverrides": [],
      "spaceLength": 10,
      "stack": false,
      "steppedLine": false,
      "targets": [
        {
          "alias": "Wazuh CPU",
          "dimensions": {},
          "expression": "",
          "id": "",
          "matchExact": true,
          "metricName": "CPUUtilization",
          "namespace": "AWS/EC2",
          "period": "",
          "refId": "A",
          "region": "${cloudwatch_region}",
          "statistics": [
            "Average"
          ]
        }
      ],
      "thresholds": [],
      "timeFrom": null,
      "timeRegions": [],
      "timeShift": null,
      "title": "SOC Components CPU Utilization",
      "tooltip": {
        "shared": true,
        "sort": 0,
        "value_type": "individual"
      },
      "type": "graph",
      "xaxis": {
        "buckets": null,
        "mode": "time",
        "name": null,
        "show": true,
        "values": []
      },
      "yaxes": [
        {
          "format": "percent",
          "label": null,
          "logBase": 1,
          "max": null,
          "min": null,
          "show": true
        }
      ]
    },
    {
      "datasource": "Elasticsearch",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "palette-classic"
          },
          "custom": {
            "axisLabel": "",
            "axisPlacement": "auto",
            "barAlignment": 0,
            "drawStyle": "line",
            "fillOpacity": 10,
            "gradientMode": "none",
            "hideFrom": {
              "legend": false,
              "tooltip": false,
              "viz": false
            },
            "lineInterpolation": "linear",
            "lineWidth": 1,
            "pointSize": 5,
            "scaleDistribution": {
              "type": "linear"
            },
            "showPoints": "never",
            "spanNulls": true
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "red",
                "value": 80
              }
            ]
          },
          "unit": "short"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 12,
        "y": 0
      },
      "id": 4,
      "options": {
        "legend": {
          "calcs": [],
          "displayMode": "list",
          "placement": "bottom"
        },
        "tooltip": {
          "mode": "single"
        }
      },
      "pluginVersion": "7.5.5",
      "targets": [
        {
          "bucketAggs": [
            {
              "field": "@timestamp",
              "id": "2",
              "settings": {
                "interval": "auto",
                "min_doc_count": 0,
                "trimEdges": 0
              },
              "type": "date_histogram"
            }
          ],
          "metrics": [
            {
              "field": "rule.level",
              "id": "1",
              "type": "avg"
            }
          ],
          "query": "rule.level:>8",
          "refId": "A",
          "timeField": "@timestamp"
        }
      ],
      "title": "High Severity Alerts Trend",
      "type": "timeseries"
    }
  ],
  "refresh": "5m",
  "schemaVersion": 27,
  "style": "dark",
  "tags": [
    "soc",
    "overview"
  ],
  "templating": {
    "list": []
  },
  "time": {
    "from": "now-24h",
    "to": "now"
  },
  "timepicker": {},
  "timezone": "",
  "title": "SOC Overview",
  "uid": "soc-overview",
  "version": 1
}
EOF

# Create Wazuh Alerts Dashboard
cat > /var/lib/grafana/dashboards/wazuh-alerts.json << EOF
{
  "annotations": {
    "list": [
      {
        "builtIn": 1,
        "datasource": "-- Grafana --",
        "enable": true,
        "hide": true,
        "iconColor": "rgba(0, 211, 255, 1)",
        "name": "Annotations & Alerts",
        "type": "dashboard"
      }
    ]
  },
  "editable": true,
  "gnetId": null,
  "graphTooltip": 0,
  "id": 2,
  "links": [],
  "panels": [
    {
      "datasource": "Elasticsearch",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "thresholds"
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "yellow",
                "value": 5
              },
              {
                "color": "orange",
                "value": 8
              },
              {
                "color": "red",
                "value": 12
              }
            ]
          }
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 0,
        "y": 0
      },
      "id": 2,
      "options": {
        "colorMode": "value",
        "graphMode": "area",
        "justifyMode": "auto",
        "orientation": "auto",
        "reduceOptions": {
          "calcs": [
            "sum"
          ],
          "fields": "",
          "values": false
        },
        "text": {},
        "textMode": "auto"
      },
      "pluginVersion": "7.5.5",
      "targets": [
        {
          "bucketAggs": [
            {
              "field": "@timestamp",
              "id": "2",
              "settings": {
                "interval": "auto"
              },
              "type": "date_histogram"
            }
          ],
          "metrics": [
            {
              "id": "1",
              "type": "count"
            }
          ],
          "query": "",
          "refId": "A",
          "timeField": "@timestamp"
        }
      ],
      "title": "Total Alerts",
      "type": "stat"
    }
  ],
  "refresh": "5m",
  "schemaVersion": 27,
  "style": "dark",
  "tags": [
    "wazuh",
    "security"
  ],
  "templating": {
    "list": []
  },
  "time": {
    "from": "now-24h",
    "to": "now"
  },
  "timepicker": {},
  "timezone": "",
  "title": "Wazuh Alerts",
  "uid": "wazuh-alerts",
  "version": 1
}
EOF

# Start Grafana service
echo "Starting Grafana service..."
systemctl enable grafana-server
systemctl start grafana-server

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
            "file_path": "/var/log/grafana/grafana.log",
            "log_group_name": "/grafana/application",
            "log_stream_name": "{instance_id}",
            "timezone": "UTC"
          },
          {
            "file_path": "/var/log/user-data.log",
            "log_group_name": "/grafana/user-data",
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
echo "Grafana installation completed successfully!"
/opt/aws/bin/cfn-signal -e 0 --stack ${project_name} --resource GrafanaAutoScalingGroup --region $(curl -s 169.254.169.254/latest/dynamic/instance-identity/document | jq -r .region)