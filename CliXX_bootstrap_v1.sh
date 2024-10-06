#!/bin/bash -x

# Logging setup
exec > >(tee /var/log/userdata.log) 2>&1

# Variables
DB_USER='wordpressuser'
DB_NAME='wordpressdb'
DB_USER_PASSWORD='W3lcome123'
DB_HOST='wordpressdbclixx.cdk4eccemey1.us-east-1.rds.amazonaws.com'
DNS='clixx-dasola.com'
FILE_SYSTEM_ID=fs-02db2efacffee0059
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
MOUNT_POINT=/var/www/html
LB_DNS='dev.clixx-dasola.com'

# Update the system and install required packages
sudo yum update -y
sudo yum install git -y
sudo amazon-linux-extras install -y lamp-mariadb10.2-php7.2 php7.2
sudo yum install -y httpd mariadb-server

# Mount EFS
mkdir -p ${MOUNT_POINT}
chown ec2-user:ec2-user ${MOUNT_POINT}
echo "${FILE_SYSTEM_ID}.efs.${REGION}.amazonaws.com:/ ${MOUNT_POINT} nfs4 nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,_netdev 0 0" >> /etc/fstab
mount -a -t nfs4
chmod -R 755 ${MOUNT_POINT}

# Start and enable Apache
sudo systemctl start httpd
sudo systemctl enable httpd
sudo systemctl start mariadb
sudo systemctl enable mariadb

# Add ec2-user to Apache group and modify permissions for /var/www
sudo usermod -a -G apache ec2-user
sudo chown -R ec2-user:apache /var/www
sudo chmod 2775 /var/www && find /var/www -type d -exec sudo chmod 2775 {} \;
find /var/www -type f -exec sudo chmod 0664 {} \;

# Clone your repository and set up WordPress configuration
cd /var/www/html
git clone https://github.com/stackitgit/CliXX_Retail_Repository.git
cp -r CliXX_Retail_Repository/* /var/www/html

# Setup wp-config.php
if [ -f "wp-config-sample.php" ]; then
    cp wp-config-sample.php wp-config.php
else
    echo "wp-config-sample.php does not exist!"
    exit 1
fi

# Replace placeholders in wp-config.php with actual values
sed -i "s/database_name_here/${DB_NAME}/g" wp-config.php
sed -i "s/username_here/${DB_USER}/g" wp-config.php
sed -i "s/password_here/${DB_USER_PASSWORD}/g" wp-config.php
sed -i "s/localhost/${DB_HOST}/g" wp-config.php

# Update Apache configuration to allow WordPress permalinks
sudo sed -i '151s/None/All/' /etc/httpd/conf/httpd.conf

# Adjust file and directory ownership and permissions
sudo chown -R apache /var/www
sudo chgrp -R apache /var/www
sudo chmod 2775 /var/www
find /var/www -type d -exec sudo chmod 2775 {} \;
find /var/www -type f -exec sudo chmod 0664 {} \;

# Check if DNS is already in the wp_options table (matching your actual setup)
output_variable=$(mysql -u ${DB_USER} -p${DB_USER_PASSWORD} -h ${DB_HOST} -D ${DB_NAME} -sse "select option_value from wp_options where option_value like '%${DNS}%';")

if [[ "${output_variable}" == "${DNS}" ]]; then
    echo "DNS Address is already in the table"
else
    echo "DNS Address is not in the table, updating..."
    mysql -u ${DB_USER} -p${DB_USER_PASSWORD} -h ${DB_HOST} -D ${DB_NAME} -e "UPDATE wp_options SET option_value ='${DNS}' WHERE option_value LIKE '%${DNS}%';"
fi

# Restart and enable Apache
sudo systemctl restart httpd

# Update RDS with Load Balancer DNS
UPDATE_SITEURL="UPDATE wp_options SET option_value='https://${LB_DNS}' WHERE option_name='siteurl';"
UPDATE_HOME="UPDATE wp_options SET option_value='https://${LB_DNS}' WHERE option_name='home';"

# Execute the update queries
mysql -h ${DB_HOST} -u ${DB_USER} -p${DB_USER_PASSWORD} -D ${DB_NAME} -e "${UPDATE_SITEURL}"
mysql -h ${DB_HOST} -u ${DB_USER} -p${DB_USER_PASSWORD} -D ${DB_NAME} -e "${UPDATE_HOME}"

# Check if MySQL query was successful
if (( $? == 0 )); then
    echo "MySQL update successful"
else
    echo "MySQL update failed"
    exit 1
fi

# Set TCP keepalive settings
sudo /sbin/sysctl -w net.ipv4.tcp_keepalive_time=200 net.ipv4.tcp_keepalive_intvl=200 net.ipv4.tcp_keepalive_probes=5
