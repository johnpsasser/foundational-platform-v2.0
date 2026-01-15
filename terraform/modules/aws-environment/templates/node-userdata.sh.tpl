#!/bin/bash
# EKS Node Bootstrap Script
# This script is injected into the launch template for EKS managed node groups

set -o xtrace

# Configure kubelet with security hardening
/etc/eks/bootstrap.sh '${cluster_name}' \
  --apiserver-endpoint '${cluster_endpoint}' \
  --b64-cluster-ca '${cluster_ca}' \
  --kubelet-extra-args '${kubelet_extra_args}' \
  --use-max-pods false

# IL5 Security Hardening

# Disable SSH password authentication
sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd

# Configure audit logging
cat >> /etc/audit/rules.d/audit.rules << 'EOF'
# Log all commands executed by users
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec

# Log file system mounts
-a always,exit -F arch=b64 -S mount -k mounts
-a always,exit -F arch=b32 -S mount -k mounts

# Log changes to system files
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k identity

# Log authentication events
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins
EOF

# Restart auditd to apply rules
service auditd restart

# Configure FIPS mode (IL5 requirement)
# Note: This should be enabled via AMI, not user data for production
# fips-mode-setup --enable

# Harden kernel parameters
cat >> /etc/sysctl.d/99-kubernetes-cis.conf << 'EOF'
# Network hardening
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1

# Disable IPv6 (if not needed)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Kernel hardening
kernel.randomize_va_space = 2
kernel.yama.ptrace_scope = 1
EOF

sysctl --system

# Configure CloudWatch agent for node metrics
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'EOF'
{
  "agent": {
    "metrics_collection_interval": 60,
    "run_as_user": "cwagent"
  },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/messages",
            "log_group_name": "/aws/eks/${cluster_name}/nodes",
            "log_stream_name": "{instance_id}/messages"
          },
          {
            "file_path": "/var/log/secure",
            "log_group_name": "/aws/eks/${cluster_name}/nodes",
            "log_stream_name": "{instance_id}/secure"
          },
          {
            "file_path": "/var/log/audit/audit.log",
            "log_group_name": "/aws/eks/${cluster_name}/nodes",
            "log_stream_name": "{instance_id}/audit"
          }
        ]
      }
    }
  },
  "metrics": {
    "namespace": "EKS/${cluster_name}",
    "metrics_collected": {
      "cpu": {
        "measurement": ["cpu_usage_active", "cpu_usage_system", "cpu_usage_user"],
        "metrics_collection_interval": 60,
        "totalcpu": true
      },
      "disk": {
        "measurement": ["used_percent", "inodes_free"],
        "metrics_collection_interval": 60,
        "resources": ["*"]
      },
      "mem": {
        "measurement": ["mem_used_percent"],
        "metrics_collection_interval": 60
      }
    }
  }
}
EOF

# Start CloudWatch agent
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json || true

echo "Bootstrap complete"
