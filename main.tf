#create vpc 
resource "aws_vpc" "main_vpc" {
  cidr_block       = var.main_vpc
  instance_tenancy = "default"

  tags = {
    Name = "main_vpc"
  }
}

#create subnets
resource "aws_subnet" "snpublic1" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = var.aws_snpublic1
  availability_zone = "us-east-2a"

  tags = {
    "Name" = "snpublic1"
  }
}

resource "aws_subnet" "snprivate1" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = var.aws_snprivate1
  availability_zone = "us-east-2a"

    tags = {
    "Name" = "snprivate1"
  }
}

resource "aws_subnet" "snpublic2" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = var.aws_snpublic2
  availability_zone = "us-east-2b"

  tags = {
  "Name" = "snpublic2" 
  }
}
resource "aws_subnet" "snprivate2" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = var.aws_snprivate2
  availability_zone = "us-east-2b"

  tags = {
  "Name" = "snprivate2" }
}

#create internet gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main_vpc.id
  tags = {
    Name = "igw"
  }
}

# Create Elastic IP
resource "aws_eip" "test_eip" {
  vpc = true

  tags = {
    Name = "test_eip"
  }
}

#create NAT gateway 
resource "aws_nat_gateway" "ngw" {
  allocation_id = aws_eip.test_eip.id
  subnet_id     = aws_subnet.snpublic1.id
  tags = {
    Name = "ngw"
  }
}
#create route table public 
resource "aws_route_table" "RT1" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

#create route table private 
resource "aws_route_table" "RT2" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.ngw.id
  }
}

# Create Route Table Association for Public Subnet1
resource "aws_route_table_association" "snpublic1_association1" {
  subnet_id      = aws_subnet.snpublic1.id
  route_table_id = aws_route_table.RT1.id
}
# Create Route Table Association for Public Subnet2
resource "aws_route_table_association" "snpublic2_association2" {
  subnet_id      = aws_subnet.snpublic2.id
  route_table_id = aws_route_table.RT1.id
}
# Create Route Table Association for Private Subnet1
resource "aws_route_table_association" "snprivate1_association3" {
  subnet_id      = aws_subnet.snprivate1.id
  route_table_id = aws_route_table.RT2.id
}

# Create Route Table Association for Private Subnet2
resource "aws_route_table_association" "snprivate2_association4" {
  subnet_id      = aws_subnet.snprivate2.id
  route_table_id = aws_route_table.RT2.id
}


#Create security groups for all server
#Security group for jenkins servers (Allows proxy and ssh)
resource "aws_security_group" "jenkins_sg" {
  name        = "jenkins_sg"
  description = "Allow HTTP and SSH inbound traffic"
  vpc_id      = aws_vpc.main_vpc.id
  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "jenkins"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "jenkins_sg"
  }
}
#Security group for docker servers 
resource "aws_security_group" "docker_sg" {
  name        = "docker_sg"
  description = "Allow HTTP and SSH inbound traffic"
  vpc_id      = aws_vpc.main_vpc.id
  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "dorker"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "docker_sg"
  }
}
  #Security group for ansible servers 
resource "aws_security_group" "ansible_sg" {
  name        = "ansible_sg"
  description = "Allow HTTP and SSH inbound traffic"
  vpc_id      = aws_vpc.main_vpc.id
  
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "ansible_sg"
  }
}
#Security group for sonarqube servers
resource "aws_security_group" "sonarqube_sg" {
  name        = "sonarqube_sg"
  description = "Allow HTTP and SSH inbound traffic"
  vpc_id      = aws_vpc.main_vpc.id
  ingress {
    description = "sonarqube"
    from_port   = 9000
    to_port     = 9000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "sonarqube_sg"
  }
}
#Security group for mysql servers
resource "aws_security_group" "mysql_sg" {
  name        = "mysql_sg"
  description = "Allow mysql traffic"
  vpc_id      = aws_vpc.main_vpc.id
  ingress {
    description = "Allow ssh traffic"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.aws_snpublic1 , var.aws_snpublic2]
  }
  ingress {
    description = "Allow mysql traffic"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = [var.aws_snpublic1 , var.aws_snpublic2]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "mysql_sg"
  }
}

# #create database subnet group
# resource "aws_db_subnet_group" "db_sn_group" {
#   name       = "test_db_sn_group"
#   subnet_ids = ["${var.aws_snprivate1.id}", "${var.aws_snprivate1.id}",]

#   tags = {
#     Name = "db_sn_group"
#   }
# }

# #Create MySQL RDS Instance
# resource "aws_db_instance" "test_rds" {
#   identifier             = "database"
#   storage_type           = "gp2"
#   allocated_storage      = 20
#   engine                 = "mysql"
#   engine_version         = "8.0"
#   instance_class         = var.db_instance_class
#   port                   = "3306"
#   db_name                = "test"
#   username               = var.database_username
#   password               = var.db_passward
#   multi_az               = true
#   parameter_group_name   = "default.mysql8.0"
#   deletion_protection    = false
#   skip_final_snapshot    = true
#   db_subnet_group_name   = aws_db_subnet_group.db_sn_group
#   vpc_security_group_ids = [aws_security_group.mysql_sg.id]
# }

#Create key pair for server
resource "aws_key_pair" "test" {
  key_name   = "test"
  public_key = file(var.test)
}

# Create the Jenkins Instance
resource "aws_instance" "jenkins_server" {
  ami                         = var.ami_redhat
  instance_type               = var.aws_instance_type
  vpc_security_group_ids      = [aws_security_group.jenkins_sg.id]
  subnet_id                   = aws_subnet.snpublic1.id
  key_name                    = var.key_name
  associate_public_ip_address = true
  user_data_replace_on_change = true
  user_data                  = <<-EOF
#!/bin/bash
sudo yum update -y
sudo yum install wget -y
sudo yum install git -y
sudo yum install maven -y
sudo wget http://get.jenkins.io/redhat/jenkins-2.346-1.1.noarch.rpm
sudo rpm -ivh jenkins-2.346-1.1.noarch.rpm
sudo yum upgrade -y
sudo yum install jenkins java-11-openjdk-devel -y --nobest
sudo yum install epel-release java-11-openjdk-devel
sudo systemctl daemon-reload
sudo systemctl start jenkins
sudo systemctl enable jenkins
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo yum update -y
sudo yum install docker-ce docker-ce-cli -y
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker ec2-user
sudo usermod -aG docker jenkins
echo "license_key:b82da2a720e6d95cc4586d2bc101fd435788NRAL" | sudo tee -a /etc/newrelic-infra.yml
sudo curl -o /etc/yum.repos.d/newrelic-infra.repo https://download.newrelic.com/infrastructure_agent/linux/yum/el/7/x86_64/newrelic-infra.repo
sudo yum -q makecache -y --disablerepo='*' --enablerepo='newrelic-infra'
sudo yum install newrelic-infra -y
sudo hostnamectl set-hostname Jenkins
EOF 
  tags = {
    Name = "jenkins_server"
  }
 }

# Create the Docker Instance
resource "aws_instance" "docker_server" {
  ami                         = var.ami_redhat
  instance_type               = var.aws_instance_type
  vpc_security_group_ids      = [aws_security_group.docker_sg.id]
  subnet_id                   = aws_subnet.snpublic1.id
  key_name                    = var.key_name
  associate_public_ip_address = true
  user_data_replace_on_change = true
  user_data                  = <<-EOF
#!/bin/bash
sudo yum update -y
sudo yum upgrade -y
sudo yum install python3 python3-pip -y
sudo alternatives --set python /usr/bin/python3
sudo pip3 install docker-py
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo yum install docker-ce docker-ce-cli -y
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker ec2-user
echo "license_key:b82da2a720e6d95cc4586d2bc101fd435788NRAL" | sudo tee -a /etc/newrelic-infra.yml
sudo curl -o /etc/yum.repos.d/newrelic-infra.repo https://download.newrelic.com/infrastructure_agent/linux/yum/el/8/x86_64/newrelic-infra.repo
sudo yum -q makecache -y --disablerepo='*' --enablerepo='newrelic-infra'
sudo yum install newrelic-infra -y
sudo su
echo "PubkeyAcceptedKeyTypes=+ssh-rsa" >> /etc/ssh/sshd_config.d/10-insecure-rsa-keysig.conf
sudo service sshd reload
chmod -R 700 .ssh/
sudo chmod 600 .ssh/authorized_keys
echo "${file(var.server_key)}" >> /home/ec2-user/.ssh/authorized_keys
sudo hostnamectl set-hostname Docker
  EOF
  tags = {
    Name = "pacpd_dockerserver"
  }
}

# Provision Ansible Host
resource "aws_instance" "ansible_server" {
  instance_type               = var.aws_instance_type
  ami                         = var.ami_redhat
  vpc_security_group_ids      = [aws_security_group.ansible_sg.id]
  subnet_id                   = aws_subnet.snpublic1.id
  key_name                    = var.key_name
  associate_public_ip_address = true
  user_data_replace_on_change = true
  user_data                  = <<-EOF
#!/bin/bash
sudo yum update -y
sudo yum upgrade -y
sudo yum install python3.8 -y
sudo alternatives --set python /usr/bin/python3.8
sudo yum -y install python3-pip
sudo yum install ansible -y
pip3 install ansible --user
sudo chown ec2-user:ec2-user /etc/ansible
#NEW RELIC SETUP
echo "license_key: b82da2a720e6d95cc4586d2bc101fd435788NRAL" | sudo tee -a /etc/newrelic-infra.yml
sudo curl -o /etc/yum.repos.d/newrelic-infra.repo https://download.newrelic.com/infrastructure_agent/linux/yum/el/7/x86_64/newrelic-infra.repo
sudo yum -q makecache -y --disablerepo='*' --enablerepo='newrelic-infra'
sudo yum install newrelic-infra -y
echo "PubkeyAcceptedKeyTypes=+ssh-rsa" >> /etc/ssh/ssh_config.d/10-insecure-rsa-keysig.conf
sudo service sshd reload
sudo bash -c ' echo "StrictHostKeyChecking No" >> /etc/ssh/ssh_config'
echo "${file(var.server_private_key)}" >> /home/ec2-user/.ssh/anskey_rsa
echo "${file(var.server_key)}" >> /home/ec2-user/.ssh/anskey_rsa.pub
sudo chmod -R 700 .ssh/
sudo chown -R ec2-user:ec2-user .ssh/
sudo yum install -y yum-utils
#DOCKER HUB CONFIGURATION
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo yum install docker-ce -y
sudo systemctl start docker
sudo usermod -aG docker ec2-user
#CHANGE OWNERSHIP OF DIRECTORY TO EC2-USER
cd /etc
sudo chown ec2-user:ec2-user hosts
cat <<EOT>> /etc/ansible/hosts
localhost ansible_connection=local
[docker_host]
${aws_instance.docker_server.public_ip}  ansible_ssh_private_key_file=/home/ec2-user/.ssh/anskey_rsa
EOT
sudo mkdir /opt/docker
sudo chown -R ec2-user:ec2-user /opt/docker
sudo chmod -R 700 /opt/docker
touch /opt/docker/Dockerfile
cat <<EOT>> /opt/docker/Dockerfile
# pull tomcat image from docker hub
FROM tomcat
FROM openjdk:8-jre-slim
#copy war file on the container
COPY spring-petclinic-2.4.2.war app/
WORKDIR app/
RUN pwd
RUN ls -al
ENTRYPOINT [ "java", "-jar", "spring-petclinic-2.4.2.war", "--server.port=8085"]
EOT
touch /opt/docker/docker-image.yml
cat <<EOT>> /opt/docker/docker-image.yml
---
 - hosts: localhost
  #root access to user
   become: true
   tasks:
   - name: login to dockerhub
     command: docker login -u cloudhight -p CloudHight_Admin123@
   - name: Create docker image from Pet Adoption war file
     command: docker build -t pet-adoption-image .
     args:
       chdir: /opt/docker
   - name: Add tag to image
     command: docker tag pet-adoption-image cloudhight/pet-adoption-image
   - name: Push image to docker hub
     command: docker push cloudhight/pet-adoption-image
   - name: Remove docker image from Ansible node
     command: docker rmi pet-adoption-image cloudhight/pet-adoption-image
     ignore_errors: yes
EOT
touch /opt/docker/docker-container.yml
cat <<EOT>> /opt/docker/docker-container.yml
---
 - hosts: docker_host
   become: true
   tasks:
   - name: login to dockerhub
     command: docker login -u cloudhight -p CloudHight_Admin123@
   - name: Stop any container running
     command: docker stop pet-adoption-container
     ignore_errors: yes
   - name: Remove stopped container
     command: docker rm pet-adoption-container
     ignore_errors: yes
   - name: Remove docker image
     command: docker rmi cloudhight/pet-adoption-image
     ignore_errors: yes
   - name: Pull docker image from dockerhub
     command: docker pull cloudhight/pet-adoption-image
     ignore_errors: yes
   - name: Create container from pet adoption image
     command: docker run -it -d --name pet-adoption-container -p 8080:8085 cloudhight/pet-adoption-image
     ignore_errors: yes
EOT
cat << EOT > /opt/docker/newrelic.yml
---
 - hosts: docker
   become: true
   tasks:
   - name: install newrelic agent
     command: docker run \
                     -d \
                     --name newrelic-infra \
                     --network=host \
                     --cap-add=SYS_PTRACE \
                     --privileged \
                     --pid=host \
                     -v "/:/host:ro" \
                     -v "/var/run/docker.sock:/var/run/docker.sock" \
                     -e NRIA_LICENSE_KEY=eu01xxbc4708e1fdb63633cc49bb88b3ce5cNRAL \
                     newrelic/infrastructure:latest
EOT
sudo hostnamectl set-hostname Ansible
EOF
  tags = {
    Name = "ansible_server"
  }
}
# SonarQube Server
resource "aws_instance" "sonarqube_server" {
  ami                         = var.ami_ubuntu
  instance_type               = var.aws_instance_type
  subnet_id                   = aws_subnet.snpublic1.id
  vpc_security_group_ids      = [aws_security_group.sonarqube_sg.id]
  key_name                    = var.key_name
  associate_public_ip_address = true
  user_data                   = local.sonarqube_user_data
  tags = {
    Name = "sonarqube_server"
  }
}

# #!bin/bash
# sudo apt-get update
# sudo hostnamectl set-hostname SonarQube
# sudo apt-get install openjdk-11-jdk -y
# echo "license_key: eu01xx7c0963548bf7c1e0573aa71a97340aNRAL" | sudo tee -a /etc/newrelic-infra.yml
# sudo curl -o /etc/yum.repos.d/newrelic-infra.repo https://download.newrelic.com/infrastructure_agent/linux/yum/el/7/x86_64/newrelic-infra.repo
# sudo yum -q makecache -y --disablerepo='*' --enablerepo='newrelic-infra'
# sudo yum install newrelic-infra -y
# sudo sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt/ `lsb_release -cs`-pgdg main" >> /etc/apt/sources.list.d/pgdg.list'
# wget -q https://www.postgresql.org/media/keys/ACCC4CF8.asc -O - | sudo apt-key add -
# sudo apt install postgresql postgresql-contrib -y
# sudo systemctl enable postgresql
# sudo systemctl start postgresql
# sudo su - postgres
# createuser sonar
# psql
# ALTER USER sonar WITH ENCRYPTED password 'pacpd';
# CREATE DATABASE sonarqube OWNER sonar;
# GRANT ALL PRIVILEGES ON DATABASE sonarqube to sonar;
# \q
# exit
# sudo apt-get install unzip -y
# sudo wget https://binaries.sonarsource.com/Distribution/sonarqube/sonarqube-8.6.0.39681.zip
# sudo unzip sonarqube*.zip -d /opt
# sudo mv /opt/sonarqube-8.6.0.39681 /opt/sonarqube -v
# sudo groupadd sonar
# sudo useradd -d /opt/sonarqube -g sonar sonar
# sudo chown sonar:sonar /opt/sonarqube -R
# sudo cat <<EOT>> /opt/sonarqube/conf/sonar.properties
# sonar.jdbc.username=sonar
# sonar.jdbc.password=pacpd
# sonar.jdbc.url=jdbc:postgresql://localhost/sonarqube
# EOT
# sudo cat <<EOT>> /opt/sonarqube/bin/linux-x86-64/sonar.sh
# RUN_AS_USER=sonar
# EOT
# sudo cat <<EOT> /etc/systemd/system/sonar.service
# [Unit]
# Description=SonarQube service
# After=syslog.target network.target

# [Service]
# Type=forking

# ExecStart=/opt/sonarqube/bin/linux-x86-64/sonar.sh start
# ExecStop=/opt/sonarqube/bin/linux-x86-64/sonar.sh stop

# User=sonar
# Group=sonar
# Restart=always

# LimitNOFILE=65536
# LimitNPROC=4096

# [Install]
# WantedBy=multi-user.target
# EOT
# sudo systemctl enable sonar
# sudo systemctl start sonar
# sudo cat <<EOT>> /etc/sysctl.conf
# vm.max_map_count=262144
# fs.file-max=65536
# ulimit -n 65536
# ulimit -u 4096
# EOT
# sudo reboot
# tail -f /opt/sonarqube/logs/sonar*.log
# EOF 
#   tags = {
#     Name = "Sonarqube_Server"
#   }
# }


resource "aws_ami_from_instance" "docker_server" {
  name               = "test-docker-server"
  source_instance_id = aws_instance.docker_server.id

depends_on = [
    aws_instance.docker_server
  ]

  tags = {
    name ="test-docker-server"
  }
}

# Create Docker_Host AMI Image
resource "aws_ami_from_instance" "pacpd_Docker_Host_AMI"{
  name                      = "pacpd_Docker_Host_AMI"
  source_instance_id    = data.aws_instance.pacpd_dockerserver.id

  depends_on = [
    aws_instance.pacpd_dockerserver,
  ]

  tags = {
    name ="pacpd_docker_host_ami"
  }
}

#Create Target group for load Balancer
resource "aws_lb_target_group" "pacpd-tg" {
  name     = "pacpd-tg"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = aws_vpc.pacpd_vpc.id 
  health_check {
    healthy_threshold    = 3
    unhealthy_threshold  = 5
    interval             = 30
    timeout              = 5
    path                 = "/"
  }
}

#Create Target group attachment
resource "aws_lb_target_group_attachment" "pacpd-tg-att" {
  target_group_arn = aws_lb_target_group.pacpd-tg.arn
  target_id        = aws_instance.pacpd_dockerserver.id
  port             = 8080

}



# Create Application Load Balancer 
resource "aws_lb" "pacpd-lb" {
  name                       = "pacpd-lb"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.pacpd_docker_sg.id]
  subnets                    = [aws_subnet.pacpd_pub_sn1.id, aws_subnet.pacpd_pub_sn2.id]
  enable_deletion_protection = false

}

# Create load balance listener
resource "aws_lb_listener" "pacpd_lb_listener" {
  load_balancer_arn = aws_lb.pacpd-lb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.pacpd-tg.arn
  }
}


#Create launch configuration
resource "aws_launch_configuration" "pacpd-lc" {
  name_prefix                 = "pacpd-lc"
  image_id                    = aws_ami_from_instance.pacpd_Docker_Host_AMI.id
  instance_type               = "t2.medium"
  security_groups             = [aws_security_group.pacpd_docker_sg.id]
  associate_public_ip_address = true
  key_name                    = var.key_name
  user_data                   = <<-EOF
  #!/bin/bash
  sudo systemctl enable docker
  sudo setenforce 0
  sudo systemctl start docker
  sudo docker start pet-adoption-container
  EOF

}

# Create Autoscaling group
resource "aws_autoscaling_group" "pacpd-asg" {
  name                      = "pacpd-asg"
  desired_capacity          = 2
  max_size                  = 4
  min_size                  = 2
  health_check_grace_period = 300
  default_cooldown          = 60
  health_check_type         = "EC2"
  force_delete              = true
  launch_configuration      = aws_launch_configuration.pacpd-lc.name
  vpc_zone_identifier       = [aws_subnet.pacpd_pub_sn1.id, aws_subnet.pacpd_pub_sn2.id]
  target_group_arns         = ["${aws_lb_target_group.pacpd-tg.arn}"]
  tag {
    key                 = "Name"
    value               = "pacpd-asg"
    propagate_at_launch = true
  }
}

# create Autoscaling group policy
resource "aws_autoscaling_policy" "pacpd-asg-pol" {
  name                   = "pacpd-asg-pol"
  policy_type            = "TargetTrackingScaling"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = aws_autoscaling_group.pacpd-asg.name
  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 60.0
  }
}  
#create route 53
resource "aws_route53_zone" "Hosted_zone" {
  name = var.domain_name

  tags = {
    Environment = "dev"
  }
}

resource "aws_route53_record" "pacpd_record" {
  zone_id = aws_route53_zone.Hosted_zone.zone_id
  name    = var.domain_name
  type    = "A"
  alias {
    name = aws_lb.pacpd-lb.dns_name
    zone_id = aws_lb.pacpd-lb.zone_id
    evaluate_target_health = true
  }
  }