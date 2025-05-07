#!/bin/bash
# modules/cortex/templates/user_data.sh.tpl

# Install dependencies
apt-get update
apt-get install -y openjdk-11-jre-headless

# Install Cortex
wget -O /tmp/cortex.deb https://github.com/TheHive-Project/Cortex/releases/download/3.1.1/cortex_3.1.1_amd64.deb
dpkg -i /tmp/cortex.deb

# Configure Cortex
cat > /etc/cortex/application.conf << EOF
# Secret key
play.http.secret.key="${admin_password}"

# Database configuration
db {
  provider: janusgraph
  janusgraph {
    storage {
      backend: berkeleyje
      directory: /var/lib/cortex/data
    }
  }
}

# Authentication configuration
auth {
  providers = [
    {name: local}
  ]
}

# Analyzers configuration
analyzer {
  # Directory where analyzers are located
  path = /opt/cortex/analyzers
}

# Responders configuration
responder {
  # Directory where responders are located
  path = /opt/cortex/responders
}
EOF

# Start Cortex
systemctl enable cortex
systemctl start cortex

# Create admin user
# (Script to create the initial admin user)