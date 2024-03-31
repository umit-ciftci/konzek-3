# Senior Level Assignment: Infrastructure as Code (IaC) and Advanced Monitoring


## 1) Terraform ile Kubernetes Cluster ve Resourcelerin oluşturulması

main.tf ile gerekli resourceleri oluşturup worker.sh ve master.sh ile clusterları ayarlıyoruz.
create-kube-cluster-terraform dosyasını oluşturup altına main.tf worker.sh ve master.sh scriplerini yazıyoruz.

- main.tf ile resourceleri oluşturuyoruz.
```
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region  = "us-east-1"
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

locals {
  name          = "Kubernetes"
  keyname       = "konzek-key-pair"
  instancetype  = "t3a.medium"
  ami           = "ami-0557a15b87f6559cf"
}

resource "aws_vpc" "my-vpc" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "my-subnet-1" {
  vpc_id     = aws_vpc.my-vpc.id
  cidr_block = "10.0.1.0/24"
}

resource "aws_subnet" "my-subnet-2" {
  vpc_id     = aws_vpc.my-vpc.id
  cidr_block = "10.0.2.0/24"
}

data "template_file" "worker" {
  template = file("${path.module}/worker.sh")
  vars = {
    region        = data.aws_region.current.name
    master_id     = aws_instance.master.id
    master_private_ip = aws_instance.master.private_ip
  }
}

data "template_file" "master" {
  template = file("${path.module}/master.sh")
}

resource "aws_instance" "master" {
  ami                  = local.ami
  instance_type        = local.instancetype
  key_name             = local.keyname
  iam_instance_profile = aws_iam_instance_profile.ec2connectprofile.name
  user_data            = data.template_file.master.rendered
  vpc_security_group_ids = [aws_security_group.tf-k8s-master-sec-gr.id]
  subnet_id            = aws_subnet.my-subnet-1.id
  tags = {
    Name = "${local.name}-kube-master"
  }
}

resource "aws_instance" "worker" {
  ami                  = local.ami
  instance_type        = local.instancetype
  key_name             = local.keyname
  iam_instance_profile = aws_iam_instance_profile.ec2connectprofile.name
  vpc_security_group_ids = [aws_security_group.tf-k8s-master-sec-gr.id]
  subnet_id            = aws_subnet.my-subnet-2.id
  user_data            = data.template_file.worker.rendered
  tags = {
    Name = "${local.name}-kube-worker"
  }
  depends_on = [aws_instance.master]
}

resource "aws_iam_instance_profile" "ec2connectprofile" {
  name = "ec2connectprofile-${local.name}"
  role = aws_iam_role.ec2connectcli.name
}

resource "aws_iam_role" "ec2connectcli" {
  name = "ec2connectcli-${local.name}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })

  inline_policy {
    name = "my_inline_policy"

    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          "Effect" : "Allow",
          "Action" : "ec2-instance-connect:SendSSHPublicKey",
          "Resource" : "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:instance/*",
          "Condition" : {
            "StringEquals" : {
              "ec2:osuser" : "ubuntu"
            }
          }
        },
        {
          "Effect" : "Allow",
          "Action" : "ec2:DescribeInstances",
          "Resource" : "*"
        }
      ]
    })
  }
}

resource "aws_security_group" "tf-k8s-master-sec-gr" {
  name = "${local.name}-k8s-master-sec-gr"
  tags = {
    Name = "${local.name}-k8s-master-sec-gr"
  }

  ingress {
    from_port = 0
    protocol  = "-1"
    to_port   = 0
    self = true
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 30000
    to_port     = 32767
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    protocol    = "-1"
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# EBS Volume
resource "aws_ebs_volume" "konzek_volume" {
  availability_zone = "us-east-1a"
  size              = 20
  tags = {
    Name = "konzek_volume"
  }
}

# S3 Bucket
resource "aws_s3_bucket" "konzek_bucket" {
  bucket = "konzek_bucket"
  acl    = "private"

  tags = {
    Name = "konzek_bucket"
  }
}

# EBS Volume Attachment
resource "aws_instance_volume_attachment" "konzek-volume-attachment" {
  device_name = "/dev/sdb"
  volume_id   = aws_ebs_volume.konzek_volume.id
  instance_id = aws_instance.master.id
}

# S3 Bucket ACL Configuration
resource "aws_s3_bucket_acl" "konzek-bucket-acl" {
  bucket = aws_s3_bucket.konzek_bucket.bucket
  acl    = "private"
}

output "master_public_dns" {
  value = aws_instance.master.public_dns
}

output "master_private_dns" {
  value = aws_instance.master.private_dns
}

output "worker_public_dns" {
  value = aws_instance.worker.public_dns
}

output "worker_private_dns" {
  value = aws_instance.worker.private_dns
}
```

- master.sh ile master nodu çalıştırırız.
 
```
#! /bin/bash
apt-get update -y
apt-get upgrade -y
hostnamectl set-hostname kube-master
apt-get install -y apt-transport-https ca-certificates curl
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list
apt-get update
apt-get install -y kubelet=1.28.1-00 kubeadm=1.28.1-00 kubectl=1.28.1-00 kubernetes-cni docker.io
apt-mark hold kubelet kubeadm kubectl
systemctl start docker
systemctl enable docker
usermod -aG docker ubuntu
newgrp docker
cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF
sysctl --system
mkdir /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml >/dev/null 2>&1
sed -i 's/SystemdCgroup \= false/SystemdCgroup \= true/g' /etc/containerd/config.toml
systemctl restart containerd
systemctl enable containerd
kubeadm config images pull
kubeadm init --pod-network-cidr=10.244.0.0/16 --ignore-preflight-errors=All
mkdir -p /home/ubuntu/.kube
cp -i /etc/kubernetes/admin.conf /home/ubuntu/.kube/config
chown ubuntu:ubuntu /home/ubuntu/.kube/config
su - ubuntu -c 'kubectl apply -f https://github.com/coreos/flannel/raw/master/Documentation/kube-flannel.yml'
```

- worker.sh  ile Kubernetes worker node Kubernetes clustera katılmak için yapılandırır.

```
#! /bin/bash
apt-get update -y
apt-get upgrade -y
hostnamectl set-hostname kube-worker
apt-get install -y apt-transport-https ca-certificates curl
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list
apt-get update
apt-get install -y kubelet=1.28.1-00 kubeadm=1.28.1-00 kubectl=1.28.1-00 kubernetes-cni docker.io
apt-mark hold kubelet kubeadm kubectl
systemctl start docker
systemctl enable docker
usermod -aG docker ubuntu
newgrp docker
cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF
sysctl --system
mkdir /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml >/dev/null 2>&1
sed -i 's/SystemdCgroup \= false/SystemdCgroup \= true/g' /etc/containerd/config.toml
systemctl restart containerd
systemctl enable containerd
wget https://bootstrap.pypa.io/get-pip.py
python3 get-pip.py
pip install pyopenssl --upgrade
pip3 install ec2instanceconnectcli
apt install -y mssh
until [[ $(mssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -t ${master-id} -r ${region} ubuntu@${master-id} kubectl get no | awk 'NR == 2 {print $2}') == Ready ]]; do echo "master node is not ready"; sleep 3; done;
kubeadm join ${master-private}:6443 --token $(mssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -t ${master-id} -r ${region} ubuntu@${master-id} kubeadm token list | awk 'NR == 2 {print $1}') --discovery-token-ca-cert-hash sha256:$(mssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -t ${master-id} -r ${region} ubuntu@${master-id} openssl x509 -pubkey -in /etc/kubernetes/pki/ca.crt | openssl rsa -pubin -outform der 2>/dev/null | openssl dgst -sha256 -hex | sed 's/^.* //') --ignore-preflight-errors=All
```

## Terraform ile Jenkins Server Kurulumu 

jenkins-server adı ile dosya oluşturup  install_jenkins.tf , install-jenkins.sh ve  variable.tf dosyalarını oluşturuyoruz.

 install_jenkins.tf:
 
```
 //This Terraform Template creates a jenkins server on AWS EC2 Instance
//Jenkins server will run on Amazon Linux 2023 with custom security group
//allowing SSH (22) and TCP (8080) connections from anywhere.
//User needs to select appropriate variables from "variable.tf" file when launching the instance.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

data "aws_ami" "al2023" {
  most_recent      = true
  owners           = ["amazon"]

  filter {
    name = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name = "architecture"
    values = ["x86_64"]
  }
  filter {
    name = "name"
    values = ["al2023-ami-2023*"]
  }
}
resource "aws_instance" "tf-jenkins-server" {
  ami           = data.aws_ami.al2023.id
  instance_type = var.instancetype
  key_name      = var.mykey
  vpc_security_group_ids = [aws_security_group.tf-jenkins-sec-gr.id]
  user_data = file("install-jenkins.sh")
  root_block_device {
    volume_size = 16
  }
  tags = {
    Name = var.tags
  }

}

resource "null_resource" "forpasswd" {
  depends_on = [aws_instance.tf-jenkins-server]

  provisioner "local-exec" {
    command = "powershell -Command Start-Sleep -Seconds 180"
  }

  # Do not forget to define your key file path correctly!
  provisioner "local-exec" {
    command = "ssh -i ~/.ssh/${var.mykey}.pem -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ec2-user@${aws_instance.tf-jenkins-server.public_ip} 'sudo cat /var/lib/jenkins/secrets/initialAdminPassword' > initialpasswd.txt"
  }
}

resource "aws_security_group" "tf-jenkins-sec-gr" {
  name = var.secgrname
  tags = {
    Name = var.secgrname
  }

  ingress {
    from_port   = 22
    protocol    = "tcp"
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 8080
    protocol    = "tcp"
    to_port     = 8080
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    protocol    = -1
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

output "jenkins" {
  value = "http://${aws_instance.tf-jenkins-server.public_ip}:8080"
}
```

variable.tf:
```
//variable "aws_secret_key" {}
//variable "aws_access_key" {}
variable "region" {
  default = "us-east-1"
}
variable "mykey" {
  default = "konzek-key-pair"
  description = "write your key pair"
}
variable "tags" {
  default = "jenkins-server"
}

variable "instancetype" {
  default = "t3a.medium"
}

variable "secgrname" {
  default = "jenkins-server-sec-gr"
}
```

#### ```terraform init```  ve    ``` terraform apply -auto-approve ``` komutları ile main.tf ve install_jenkins.tf dosyalarının dizininde serverları ayağa kaldırırız.

install-jenkins.sh:
```
#! /bin/bash
dnf update -y
wget -O /etc/yum.repos.d/jenkins.repo https://pkg.jenkins.io/redhat-stable/jenkins.repo
rpm --import https://pkg.jenkins.io/redhat-stable/jenkins.io-2023.key
dnf upgrade -y
dnf install fontconfig java-17-amazon-corretto-devel -y
dnf install jenkins -y
systemctl daemon-reload
systemctl enable jenkins
systemctl start jenkins
systemctl status jenkins
dnf install git -y
```
Jenkins sunucusunun otomatik olarak kurulumunu gerçekleştirir ve Jenkins servisini başlatır. Ayrıca Jenkins'in çalışması için gereken diğer bağımlılıkları da sağlar.





## CI/CD pipeline 

jenkins\Jenkinsfile dosyasını oluşturup içine yazarız.

```
pipeline {
  agent any

  options {
    buildDiscarder(logRotator(numToKeepStr: '3'))
    disableConcurrentBuilds()
    timestamps()
  }

  triggers {
    githubWebhook()
  }

  stages {
    stage('Initialize Terraform') {
      steps {
        sh 'terraform init'
      }
    }

    stage('Test Infrastructure Changes') {
      steps {
        script {
          def terraformPlan = sh(script: 'terraform plan', returnStatus: true)
          if (terraformPlan == 0) {
            echo 'Infrastructure changes tested successfully!'
          } else {
            error 'Failed to test infrastructure changes'
          }
        }
      }
    }

    stage('Apply Infrastructure Changes') {
      steps {
        script {
          def terraformApply = sh(script: 'terraform apply -auto-approve', returnStatus: true)
          if (terraformApply == 0) {
            echo 'Infrastructure changes applied successfully!'
          } else {
            error 'Failed to apply infrastructure changes'
          }
        }
      }
    }
  }

  post {
    failure {
      script {
        def terraformError = sh(script: 'terraform apply -auto-approve', returnStdout: true)
        echo "Terraform apply failed with the following error: ${terraformError}"
      }
    }
  }
}

```

Jenkins Servera bağlandıktan sonra 

 - Go to the Jenkins dashboard and click on `New Item` to create a pipeline.

 - Enter `CI/CD-pipeline` then select `Pipeline` and click `OK`.

- Pipeline:
    Definition: Pipeline script from SCM
    SCM: Git
      Repositories:
        - Repository URL: https://github.com/umit-ciftci/konzek-3.git
        - Branches to build: 
            Branch Specifier: */main

    Script Path: Jenkinsfile
  
   olacak şekilde ayarlarız. Ayrıca Jenkinsfile ile  Terraform state dosyasını S3de saklamak istersek diye Jenkinsfilde bu ekleme yazabiliriz.


```
    pipeline {
    agent any

    options {
        buildDiscarder(logRotator(numToKeepStr: '3'))
        disableConcurrentBuilds()
        timestamps()
    }

    stages {
        stage('Checkout Code') {
            steps {
                checkout scm
            }
        }

        stage('Upload to S3 Bucket') {
            steps {
                script {
                    def awsAccessKeyId = env.AWS_ACCESS_KEY_ID
                    def awsSecretAccessKey = env.AWS_SECRET_ACCESS_KEY
                    def region = 'us-east-1'
                    def bucketName = 'konzek_bucket'

                    // Set AWS credentials
                    withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', accessKeyVariable: 'AWS_ACCESS_KEY_ID', credentialsId: 'aws-credentials-id', secretKeyVariable: 'AWS_SECRET_ACCESS_KEY']]) {
                        // Upload files to S3 bucket
                        sh "aws s3 cp your_file_path s3://${bucketName}/your_destination_path --region ${region}"
                    }
                }
            }
        }

        // Add more stages as needed
    }
}
```

GitHub ile Webhook Ayarlarını Yapın:

- GitHub hesabınıza gidin ve projenize girin.
- Üst menüden "Settings" (Ayarlar) seçeneğine tıklayın ve ardından "Webhooks" (Web Kancaları) sekmesine gidin.
- "Add Webhook" (Webhook Ekle) düğmesine tıklayın.
- "Payload URL" alanına Jenkins'in Webhook URL'sini girin. Bu URL genellikle http://jenkins-server/github-webhook/ şeklindedir.
- "Content type" alanını application/json olarak ayarlayın.
- Hangi olayların Jenkins'e bildirim göndermesini istediğinizi seçin (örneğin, push, pull request, vb.).
- Webhook'u eklemek için "Add Webhook" veya benzeri bir düğmeye tıklayın.


 ## Monitoring-server kurulumu

Monitoring-server\Prometheus-install.sh ile  Prometheus kurulumu yapıyoruz.

``` kubectl cluster-info  #Check if Kubernetes is running. ```
```
curl https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash  #Install Helm.
helm version
```
```
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts #Get prometheus helm repository Info.
helm repo update
```
```
helm install prometheus prometheus-community/prometheus #Install chart.
```

```
#Check the prometheus objects.
kubectl get deploy
kubectl get daemonset
kubectl get pod
kubectl get svc
```
#Edit `prometheus-server` service to reach promethes server from external as below.
```
kubectl edit svc prometheus-server
```
Change the service type as `NodePort` and add `nodePort: 30001` port to `ports` field.
Open web browser and go to **http://ec2-54-89-159-197.compute-1.amazonaws.com:30001/**
!!!Note
Replace the address with your EC2 Master Node's public IP address.

 Monitoring-server\grafana-install.sh ile Grafana kurulumunu yapıyoruz.
 
#Install grafana according to the HELM artifacthub (https://artifacthub.io/packages/helm/grafana/grafana).
# Get grafana helm repository Info.
```
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update
```

#Install chart.
```
helm install grafana grafana/grafana
```
```
#Check the grafana objects.
kubectl get deploy grafana
kubectl get po | grep "grafana"
kubectl get svc grafana
```
```
#Edit `grafana` service to reach grafana from external as below.
kubectl edit svc grafana
```
Change the service type as `NodePort` and add `nodePort: 30002` port to `ports` field.
Open web browser and go to **http://ec2-54-89-159-197.compute-1.amazonaws.com:30002/**
!!! Note
Replace the address with your EC2 Master Node's public IP address.

###Log in for the First Time
#Get the `admin-password` and `admin-user`.
kubectl get secret grafana -o yaml

#Decode the `admin-password` and `admin-user` as below.
echo "YWRtaW4=" | base64 -d ; echo
echo "dFozeEV6bGFxUWUyODFoeDhSamlRQmdqM2l5eVFJTmFybURub0tBdQ==" | base64 -d ; echo

###Add Prometheus as a Data Source

- Click ***DATA SOURCES*** and you will come to the settings page of your new data source.

- Select ***Prometheus***

- Write `http://prometheus-server:80` for URL. (You don't need to define service port 80, because it is default port.) Then click ***Save & Test***.

- Click ***Dashboards***.

- Click `New` and `Import` buttons.

- Select a dashboard ID on `https://grafana.com/grafana/dashboards/` page like `6417`.

- Select `promethes` as data source.

###Add CloudWatch as a Data Source

- Move your cursor to the cog on the side menu which will show you the configuration menu. Click on ***Configuration > Data Sources*** in the side menu and you’ll be taken to the data sources page where you can add and edit data sources.

- Click ***Add data source*** and you will come to the settings page of your new data source.

- Select ***CloudWatch***.

- For ***Auth Provider***, Choose ***Access & secret key***.

- Write your ***Access Key ID*** and ***Secret Access Key***.

- Write your ***Default Region***.

- Click ***Save & Test***.

- Click ***Dashboards*** (next to the Setting).

- Import ***Amazon EC2*** and ***Amazon CloudWatch Logs***.

- Click ***Home*** then ***Amazon EC2***.

- Click ***Network Detail*** to see Network traffic.

###Create a New Dashboard

- In the side bar, hover your cursor over the Create (plus sign) icon and then click ***Dashboard***.

- Click ***Add new panel***.

- Click ***Visualization*** (Left Side) and then select ***Gauge***.

- Query Mode : CloudWatch Metrics
- Region : default
- Namespace : AWS/EC2
- Metric Name : CPUUtilization
- Stats : Average
- Dimentions : InstanceId = "Insctance ID"
- Click ***Apply***


Monitoring-server\alertmanager.yml dosyasını oluşturuyoruz.
```
apiVersion: v1
items:
- apiVersion: v1
  data:
    admin: MTIzNA==
    token: WVNzZGVkIEFkbWlu==
  kind: Secret
  metadata:
    labels:
      app.kubernetes.io/name: alertmanager-bot
    name: alertmanager-bot
    namespace: monitoring
  type: Opaque
- apiVersion: v1
  kind: Service
  metadata:
    labels:
      app.kubernetes.io/name: alertmanager-bot
    name: alertmanager-bot
    namespace: monitoring
  spec:
    ports:
    - name: http
      port: 8080
      targetPort: 8080
    selector:
      app.kubernetes.io/name: alertmanager-bot
- apiVersion: apps/v1
  kind: StatefulSet
  metadata:
    labels:
      app.kubernetes.io/name: alertmanager-bot
    name: alertmanager-bot
    namespace: monitoring
  spec:
    podManagementPolicy: OrderedReady
    replicas: 1
    selector:
      matchLabels:
        app.kubernetes.io/name: alertmanager-bot
    serviceName: alertmanager-bot
    template:
      metadata:
        labels:
          app.kubernetes.io/name: alertmanager-bot
        name: alertmanager-bot
        namespace: monitoring
      spec:
        containers:
        - args:
          - --alertmanager.url=http://localhost:9093
          - --log.level=info
          - --store=bolt
          - --bolt.path=/data/bot.db
          - --slack.token=WSNzZGVkIFN0YW5kTm9kZQ==   #Kendi Tokenınız ile güncelleyin.
          - --slack.channel=your-slack-channel         #Channel ayarlayınız.
          env:
          - name: TELEGRAM_ADMIN
            valueFrom:
              secretKeyRef:
                key: admin
                name: alertmanager-bot
          - name: TELEGRAM_TOKEN
            valueFrom:
              secretKeyRef:
                key: token
                name: alertmanager-bot
          image: metalmatze/alertmanager-bot:0.4.3
          imagePullPolicy: IfNotPresent
          name: alertmanager-bot
          ports:
          - containerPort: 8080
            name: http
          resources:
            limits:
              cpu: 100m
              memory: 128Mi
            requests:
              cpu: 25m
              memory: 64Mi
          volumeMounts:
          - mountPath: /data
            name: data
        restartPolicy: Always
        volumes:
        - name: data
          persistentVolumeClaim:
            claimName: alertmanager-bot
    volumeClaimTemplates:
    - apiVersion: v1
      kind: PersistentVolumeClaim
      metadata:
        labels:
          app.kubernetes.io/name: alertmanager-bot
        name: alertmanager-bot
        namespace: monitoring
      spec:
        accessModes:
        - ReadWriteOnce
        resources:
          requests:
            storage: 1Gi
        storageClassName: standard
kind: List
```
Bu sayede Slackede bağlamış olacağız.

Monitoring-server\alert.rules.yml  dosyasını oluşturup gerekli ayarlamayı yapacağız.

```
groups:
- name: example
  rules:
  - alert: HighCPUUsage
    expr: node_cpu_seconds_total / node_schedulable_cpus > 0.8
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "High CPU Usage"
      description: "CPU usage is above 80% on instance {{$labels.instance}}"
```
Bu prometheus.yml dosyasına eklenmesi gereken bir örnek uyarı kuralıdır. Bu kural, CPU kullanımının belirli bir eşiği aştığında bir uyarı oluşturur.
Genellikle, Prometheus'un yapılandırma dosyasındaki rule_files bölümüne eklenir. Bu bölüm, Prometheus'un izleyeceği ek bir kural dosyasını tanımlar.
rule_files:
  - "alert.rules.yml"
Bu şekilde ayarlama yaparak  alert.rules.yml doğrultusunda bağlanır.
Bu dosyayı Prometheus'un yapılandırma dosyasının olduğu dizine kaydedin ve ardından Prometheus'u yeniden başlatın veya yeniden yükleyin. Bu şekilde, yeni uyarı kuralı Prometheus tarafından izlenmeye başlanacaktır.







