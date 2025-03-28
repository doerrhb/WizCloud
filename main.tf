# This is my terraform file for my Wiz Tech Screen.
terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = "us-east-2"
}

provider "aws" {
  alias  = "us_east_2"
  region = "us-east-2"
}

# Fetch availability zones
data "aws_availability_zones" "available" {}

# VPC
resource "aws_vpc" "tasky_vpc" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "tasky-vpc"
  }
}

# Subnets
resource "aws_subnet" "tasky_subnet" {
  count             = 2
  vpc_id            = aws_vpc.tasky_vpc.id
  cidr_block        = cidrsubnet(aws_vpc.tasky_vpc.cidr_block, 8, count.index)
  availability_zone = element(data.aws_availability_zones.available.names, count.index)
  map_public_ip_on_launch = true

  tags = {
    Name = "tasky-subnet-${count.index}"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "tasky_igw" {
  vpc_id = aws_vpc.tasky_vpc.id

  tags = {
    Name = "tasky-igw"
  }
}

# Route Table
resource "aws_route_table" "tasky_route_table" {
  vpc_id = aws_vpc.tasky_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.tasky_igw.id
  }

  tags = {
    Name = "tasky-route-table"
  }
}

# Route Table Associations
resource "aws_route_table_association" "tasky_route_table_association" {
  count          = length(aws_subnet.tasky_subnet)
  subnet_id      = element(aws_subnet.tasky_subnet.*.id, count.index)
  route_table_id = aws_route_table.tasky_route_table.id
}

# Security Group for EKS
resource "aws_security_group" "eks_security_group" {
  vpc_id = aws_vpc.tasky_vpc.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "eks-security-group"
  }
}

# IAM role for EKS Cluster
resource "aws_iam_role" "eks_cluster_role" {
  name = "eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster_role.name
}

# IAM role for EKS Node Group
resource "aws_iam_role" "eks_node_role" {
  name = "eks-node-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "eks_node_AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_node_role.name
}

resource "aws_iam_role_policy_attachment" "eks_node_AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_node_role.name
}

resource "aws_iam_role_policy_attachment" "eks_node_AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_node_role.name
}

# IAM role for MongoDB backup to S3
resource "aws_iam_role" "mongo_backup_role" {
  name = "mongo-backup-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "mongo_backup_policy" {
  name        = "mongo-backup-policy"
  description = "Policy for MongoDB backup to S3"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Effect   = "Allow"
        Resource = [
          aws_s3_bucket.mongodb_backup_bucket.arn,
          "${aws_s3_bucket.mongodb_backup_bucket.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "mongo_backup_policy_attachment" {
  role       = aws_iam_role.mongo_backup_role.name
  policy_arn = aws_iam_policy.mongo_backup_policy.arn
}

# S3 bucket for MongoDB backups with a unique name
resource "aws_s3_bucket" "mongodb_backup_bucket" {
  bucket = "mongodb-backup-bucket-${random_id.bucket_id.hex}"

  tags = {
    Name        = "mongodb-backup-bucket"
    Environment = "Dev"
  }
}

resource "random_id" "bucket_id" {
  byte_length = 8
}

resource "aws_s3_bucket_lifecycle_configuration" "mongodb_backup_bucket_lifecycle" {
  provider = aws.us_east_2
  bucket   = aws_s3_bucket.mongodb_backup_bucket.bucket

  rule {
    id      = "log"
    status  = "Enabled"

    filter {
      prefix = ""
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 365
    }
  }
}

# EKS Cluster
resource "aws_eks_cluster" "tasky_cluster" {
  name     = "tasky-cluster"
  role_arn = aws_iam_role.eks_cluster_role.arn

  vpc_config {
    subnet_ids = aws_subnet.tasky_subnet[*].id
  }
}

# EKS Node Group
resource "aws_eks_node_group" "tasky_node_group" {
  cluster_name    = aws_eks_cluster.tasky_cluster.name
  node_group_name = "tasky-node-group"
  node_role_arn   = aws_iam_role.eks_node_role.arn
  subnet_ids      = aws_subnet.tasky_subnet[*].id

  scaling_config {
    desired_size = 2
    max_size     = 3
    min_size     = 1
  }
}

# Security Group for MongoDB EC2 Instance
resource "aws_security_group" "mongodb_security_group" {
  vpc_id = aws_vpc.tasky_vpc.id

  ingress {
    from_port   = 27017
    to_port     = 27017
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Allow MongoDB access from anywhere (consider restricting this for security)
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Allow SSH access from anywhere (restrict to your IP for better security)
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "mongodb-security-group"
  }
}

# Security Group for HTTP and HTTPS
resource "aws_security_group" "http_https_security_group" {
  vpc_id = aws_vpc.tasky_vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
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
    Name = "http-https-security-group"
  }
}

# IAM Role for EC2 Instance
resource "aws_iam_role" "mongodb_instance_role" {
  name = "mongodb-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}


# Attach S3 Access Policy to the Role
resource "aws_iam_role_policy_attachment" "mongodb_instance_s3_access" {
  role       = aws_iam_role.mongodb_instance_role.name
  policy_arn = aws_iam_policy.mongo_backup_policy.arn
}

# Create an Instance Profile for the Role
resource "aws_iam_instance_profile" "mongodb_instance_profile" {
  name = "mongodb-instance-profile"
  role = aws_iam_role.mongodb_instance_role.name
}

# EC2 Instance for MongoDB with updated AMI ID
resource "aws_instance" "mongodb_instance" {
  ami                    = "ami-058e977e6a7dc2a4c" # Amazon Linux 2 AMI for us-east-2
  instance_type          = "t3.micro"
  subnet_id              = element(aws_subnet.tasky_subnet.*.id, 0)
  vpc_security_group_ids = [aws_security_group.mongodb_security_group.id]
  key_name               = "wizkey" # Replace with your existing key pair name
  iam_instance_profile   = aws_iam_instance_profile.mongodb_instance_profile.name

  tags = {
    Name = "mongodb-instance"
  }

user_data = <<-EOF
              #!/bin/bash
              set -e
              exec > >(tee /var/log/user_data.log|logger -t user_data -s 2>/dev/console) 2>&1

              # Update the system
              yum update -y

              # Enable and install MongoDB
              amazon-linux-extras enable epel
              yum install -y epel-release
              cat <<EOL > /etc/yum.repos.d/mongodb-org-4.4.repo
              [mongodb-org-4.4]
              name=MongoDB Repository
              baseurl=https://repo.mongodb.org/yum/amazon/2/mongodb-org/4.4/x86_64/
              gpgcheck=1
              enabled=1
              gpgkey=https://www.mongodb.org/static/pgp/server-4.4.asc
              EOL
              yum install -y mongodb-org

              # Overwrite MongoDB bindIp to allow connections from any IP
              cat <<EOL > /etc/mongod.conf
              systemLog:
                destination: file
                logAppend: true
                path: /var/log/mongodb/mongod.log
              storage:
                dbPath: /var/lib/mongo
                journal:
                  enabled: true
              net:
                port: 27017
                bindIp: 0.0.0.0
              processManagement:
                timeZoneInfo: /usr/share/zoneinfo
              EOL

              # Start and enable MongoDB
              systemctl start mongod
              systemctl enable mongod

              # Install EC2 Instance Connect and AWS CLI
              yum install -y ec2-instance-connect aws-cli

              # Configure MongoDB user
              mongo <<EOF2
              use admin
              db.createUser({
                user: "wizdba",
                pwd: "wizdba123",
                roles: [ { role: "userAdminAnyDatabase", db: "admin" } ]
              })
              EOF2

              # Create backup script
              cat <<'BACKUP_SCRIPT' > /usr/local/bin/mongodb_backup.sh
              #!/bin/bash
              BACKUP_DIR="/var/backups/mongodb"
              S3_BUCKET="s3://mongodb-backup-bucket-${random_id.bucket_id.hex}"
              TIMESTAMP=$(date +%Y%m%d%H%M%S)
              BACKUP_FILE="$BACKUP_DIR/mongodb-$TIMESTAMP.gz"
              LOG_FILE="/var/log/mongodb_backup.log"

              # Create backup directory if it doesn't exist
              mkdir -p $BACKUP_DIR

              # Perform MongoDB backup
              echo "Starting MongoDB backup at $(date)" >> $LOG_FILE
              mongodump --archive=$BACKUP_FILE --gzip >> $LOG_FILE 2>&1

              # Upload backup to S3
              echo "Uploading $BACKUP_FILE to $S3_BUCKET" >> $LOG_FILE
              aws s3 cp $BACKUP_FILE $S3_BUCKET/ >> $LOG_FILE 2>&1
              if [ $? -ne 0 ]; then
                echo "Failed to upload $BACKUP_FILE to $S3_BUCKET" >> $LOG_FILE
                exit 1
              fi

              # Rotate backups (keep at most 5)
              echo "Rotating backups in $BACKUP_DIR" >> $LOG_FILE
              ls -1t $BACKUP_DIR/mongodb-*.gz | tail -n +6 | xargs rm -f >> $LOG_FILE 2>&1
              BACKUP_SCRIPT

              chmod +x /usr/local/bin/mongodb_backup.sh

              # Schedule cron job to run every 30 minutes
              echo "*/30 * * * * root /usr/local/bin/mongodb_backup.sh" > /etc/cron.d/mongodb-backup
              chmod 0644 /etc/cron.d/mongodb-backup
              crontab /etc/cron.d/mongodb-backup

              # Trigger an initial backup
              /usr/local/bin/mongodb_backup.sh
EOF
}

# Kubernetes provider
provider "kubernetes" {
  host                   = aws_eks_cluster.tasky_cluster.endpoint
  cluster_ca_certificate = base64decode(aws_eks_cluster.tasky_cluster.certificate_authority.0.data)
  token                  = data.aws_eks_cluster_auth.tasky_cluster.token
}

data "aws_eks_cluster_auth" "tasky_cluster" {
  name = aws_eks_cluster.tasky_cluster.name
}

# Create Kubernetes deployment and service for the web application
resource "kubernetes_deployment" "tasky_app" {
  metadata {
    name      = "tasky-app"
    namespace = "default"
    labels = {
      app = "tasky"
    }
  }

  spec {
    replicas = 2

    selector {
      match_labels = {
        app = "tasky"
      }
    }

    template {
      metadata {
        labels = {
          app = "tasky"
        }
      }

      spec {
        container {
          name  = "tasky-app"
          image = "jeffthorne/tasky:latest"
          port {
            container_port = 8080
          }
          env {
            # MongoDB connection string
            name  = "MONGODB_URI"
            value = "mongodb://wizdba:wizdba123@${aws_instance.mongodb_instance.private_ip}:27017"
          }
          env {
            # Secret key for the application
            name  = "SECRET_KEY"
            value = "secret123"
          }
        }
      }
    }
  }
}

resource "kubernetes_service" "tasky_service" {
  metadata {
    name      = "tasky-service"
    namespace = "default"
    labels = {
      app = "tasky"
    }
    annotations = {
      "service.beta.kubernetes.io/aws-load-balancer-security-groups" = aws_security_group.http_https_security_group.id
    }
  }

  spec {
    selector = {
      app = "tasky"
    }

    port {
      port        = 80
      target_port = 8080
    }

    type = "LoadBalancer"
  }
}

# Output the public URL of the web application
output "tasky_app_url" {
  value       = kubernetes_service.tasky_service.status[0].load_balancer[0].ingress[0].hostname
  description = "The public URL of the Tasky web application"
}
# Output the name of the S3 bucket used for MongoDB backups
output "mongodb_backup_bucket_name" {
  value       = aws_s3_bucket.mongodb_backup_bucket.bucket
  description = "The name of the S3 bucket used for MongoDB backups"
}

# Output the command to list the contents of the S3 bucket
output "mongodb_backup_bucket_contents" {
  value       = "Run the following command to list the contents of the S3 bucket:\naws s3 ls s3://${aws_s3_bucket.mongodb_backup_bucket.bucket}/"
  description = "Command to list the contents of the MongoDB backup S3 bucket"
}