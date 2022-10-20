#Vpc  
variable "main_vpc" {
  default = "10.0.0.0/16"
}
#Public Subnet 1
variable "aws_snpublic1" {
  default = "10.0.1.0/24"
}

#Public Subnet 2
variable "aws_snpublic2" {
  default = "10.0.3.0/24"
}

#Private Subnet 1
variable "aws_snprivate1" {
  default = "10.0.2.0/24"
}

#Private Subnet 2
variable "aws_snprivate2" {
  default = "10.0.4.0/24"
}

#private keypair
variable "test" {
  default = "/Users/administrator/Desktop/devops/petadoption/test.pub"
}
#publickey
variable "server_key" {
  default = "/Users/administrator/Desktop/devops/petadoption/test.pub"
}

#privatkey
variable "server_private_key" {
  default = "/Users/administrator/Desktop/devops/petadoption/test"
}
 
variable "aws_instance_type" {
  default = "t2.medium"
}

variable "key_name" {
  default = "test"
}

variable "ami_ubuntu" {
  default = "ami-097a2df4ac947655f" 
}

variable "ami_redhat" {
  default = "ami-092b43193629811af" 
}

variable "database_username" {
  default = "test"
}

variable "db_passward" {
  default = "Admin123"
}

variable "Domine_name" {
  default = "onconsult.top"
}
