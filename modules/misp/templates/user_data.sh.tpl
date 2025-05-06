#!/bin/bash
# File: modules/misp/templates/user_data.sh.tpl

# Exit immediately if a command exits with a non-zero status
set -e

# Log all output
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

echo "Starting MISP installation process..."

# Update system
apt-get update
apt-get upgrade -y
apt-get install -y curl wget gnupg git unzip apt-transport-https ca-certificates software-properties-common python3 python3-pip

# Install AWS CLI
pip3 install --upgrade awscli

# Set hostname
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
hostnamectl set-hostname misp-$INSTANCE_ID

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

# Create MISP user
echo "Creating MISP user..."
useradd -m -s /bin/bash misp
usermod -aG docker misp

# Create MISP directories
echo "Creating MISP directories..."
mkdir -p /opt/misp/data
mkdir -p /opt/misp/config
mkdir -p /opt/misp/logs
mkdir -p /opt/misp/ssl
chown -R misp:misp /opt/misp

# Generate SSL certificates for MISP
echo "Generating SSL certificates..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /opt/misp/ssl/misp.key \
  -out /opt/misp/ssl/misp.crt \
  -subj "/C=US/ST=State/L=City/O=${org_name}/CN=misp.${domain_name}"

# Create Docker Compose file
echo "Creating Docker Compose file..."
cat > /opt/misp/docker-compose.yml << EOF
version: '3'

services:
  misp:
    image: coolacid/misp-docker:core-${misp_version}
    container_name: misp
    restart: unless-stopped
    depends_on:
      - redis
    ports:
      - "443:443"
    volumes:
      - /opt/misp/config:/var/www/MISP/app/Config
      - /opt/misp/data:/var/www/MISP/app/files
      - /opt/misp/ssl:/etc/nginx/certs
    environment:
      - MYSQL_HOST=${db_endpoint}
      - MYSQL_USER=${db_user}
      - MYSQL_PASSWORD=${db_password}
      - MYSQL_DATABASE=${db_name}
      - REDIS_FQDN=redis
      - MISP_ADMIN_EMAIL=${admin_email}
      - MISP_ADMIN_PASSPHRASE=${admin_password}
      - MISP_BASEURL=https://misp.${domain_name}
      - TIMEZONE=UTC
      - "INIT=true"
      - "CRON_USER_ID=1"
      - "DISIPV6=true"
      - "NOREDIR=true"
      - "SECURESSL=true"
    environment:
      - TZ=UTC

  redis:
    image: redis:6.2.7
    container_name: misp-redis
    restart: unless-stopped
    command: redis-server --appendonly yes --maxmemory 256mb --maxmemory-policy allkeys-lru
    volumes:
      - redis-data:/data

volumes:
  redis-data:
EOF

# Custom MISP configuration
echo "Setting up MISP configuration..."
mkdir -p /opt/misp/config/database
cat > /opt/misp/config/database/config.php << EOF
<?php
class DATABASE_CONFIG {
  public \$default = array(
    'datasource' => 'Database/Mysql',
    'persistent' => false,
    'host' => '${db_endpoint}',
    'login' => '${db_user}',
    'port' => 3306,
    'password' => '${db_password}',
    'database' => '${db_name}',
    'prefix' => '',
    'encoding' => 'utf8',
  );
}
EOF

# Create MISP configuration
mkdir -p /opt/misp/config
cat > /opt/misp/config/config.php << EOF
<?php
\$config = array(
  'debug' => 0,
  'Security' => array(
    'salt' => '$(openssl rand -hex 32)',
    'cipherSeed' => '$(openssl rand -hex 32)',
  ),
  'MISP' => array(
    'baseurl' => 'https://misp.${domain_name}',
    'email' => 'no-reply@${domain_name}',
    'contact' => '${admin_email}',
    'organization' => '${org_name}',
    'background_jobs' => true,
    'cached_attachments' => true,
  ),
  'GnuPG' => array(
    'email' => '${admin_email}',
    'homedir' => '/var/www/MISP/.gnupg',
    'password' => '',
  ),
  'Plugin' => array(
    'ZeroMQ_enable' => false,
    'ZeroMQ_redis_host' => 'redis',
    'ZeroMQ_redis_port' => 6379,
    'ZeroMQ_redis_database' => 1,
    'ZeroMQ_redis_namespace' => 'mispq',
    'ZeroMQ_redis_password' => '',
    'ZeroMQ_redis_vm' => '',
    'ZeroMQ_redis_vm_dtls' => '',
  ),
);
EOF

# Nginx SSL configuration
mkdir -p /opt/misp/config/nginx
cat > /opt/misp/config/nginx/misp.conf << EOF
server {
    listen 80;
    server_name misp.${domain_name};
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name misp.${domain_name};
    
    ssl_certificate /etc/nginx/certs/misp.crt;
    ssl_certificate_key /etc/nginx/certs/misp.key;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'";
    
    client_max_body_size 50M;
    
    root /var/www/MISP/app/webroot;
    index index.php;
    
    location / {
        try_files \$uri \$uri/ /index.php\$is_args\$args;
    }
    
    location ~ \.php$ {
        try_files \$uri =404;
        include fastcgi_params;
        fastcgi_pass 127.0.0.1:9000;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_read_timeout 300;
    }
    
    location ~ \.(gif|jpg|png|css|js)$ {
        expires max;
    }
}
EOF

# Start MISP
echo "Starting MISP..."
cd /opt/misp
docker-compose up -d

# Wait for MISP to initialize
echo "Waiting for MISP to initialize..."
sleep 30

# Check if MISP is running
until curl -sk https://localhost/users/login > /dev/null; do
  echo "Waiting for MISP to become available..."
  sleep 10
done

echo "MISP has started successfully"

# Create automation key and store it in SSM
echo "Creating automation key..."
sleep 30  # Give MISP a bit more time to fully initialize before creating the key

# Get auth key for API
AUTH_KEY=$(docker exec misp /var/www/MISP/app/Console/cake admin getAuthKey admin@admin.test | tail -1)

# Store the API key in SSM Parameter Store
if [ ! -z "$AUTH_KEY" ]; then
  aws ssm put-parameter \
    --name "/${project_name}/misp/api_key" \
    --type "SecureString" \
    --value "$AUTH_KEY" \
    --overwrite \
    --region $(curl -s 169.254.169.254/latest/dynamic/instance-identity/document | jq -r .region)
    
  echo "MISP API key stored in Parameter Store"
else
  echo "Failed to retrieve MISP API key"
fi

# Set up MISP feeds
echo "Setting up MISP feeds..."

# Enable feeds (using the API key)
curl -sk -X POST https://localhost/feeds/enable/1 \
  -H "Authorization: $AUTH_KEY" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json"

# Configure some common threat feeds
FEEDS=(
  '{"Feed":{"name":"CIRCL OSINT Feed","provider":"CIRCL","url":"https://www.circl.lu/doc/misp/feed-osint","source_format":"misp"}}'
  '{"Feed":{"name":"Botvrij.eu OSINT Feed","provider":"Botvrij.eu","url":"https://www.botvrij.eu/data/feed-osint","source_format":"misp"}}'
  '{"Feed":{"name":"MISP warninglist","provider":"MISP","url":"https://github.com/MISP/misp-warninglists","source_format":"csv"}}'
)

for feed in "${FEEDS[@]}"; do
  curl -sk -X POST https://localhost/feeds/add \
    -H "Authorization: $AUTH_KEY" \
    -H "Accept: application/json" \
    -H "Content-Type: application/json" \
    -d "$feed"
done

# Setup warninglists
echo "Setting up MISP warninglists..."
curl -sk -X POST https://localhost/warninglists/update \
  -H "Authorization: $AUTH_KEY" \
  -H "Accept: application/json"

# Setup taxonomies
echo "Setting up MISP taxonomies..."
curl -sk -X POST https://localhost/taxonomies/update \
  -H "Authorization: $AUTH_KEY" \
  -H "Accept: application/json"

# Setup galaxies
echo "Setting up MISP galaxies..."
curl -sk -X POST https://localhost/galaxies/update \
  -H "Authorization: $AUTH_KEY" \
  -H "Accept: application/json"

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
            "log_group_name": "/misp/user-data",
            "log_stream_name": "{instance_id}",
            "timezone": "UTC"
          },
          {
            "file_path": "/opt/misp/logs/*.log",
            "log_group_name": "/misp/application",
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
echo "MISP installation completed successfully!"
/opt/aws/bin/cfn-signal -e 0 --stack ${project_name} --resource MispAutoScalingGroup --region $(curl -s 169.254.169.254/latest/dynamic/instance-identity/document | jq -r .region)