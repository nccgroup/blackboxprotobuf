# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "hashicorp/bionic64"

  config.vm.synced_folder "./", "/vagrant", disabled: true

  config.vm.synced_folder "./", "/home/vagrant/blackboxprotobuf", type: "rsync"
  config.vm.provision "shell", inline: <<-SHELL
    sudo apt-get update
    sudo apt-get install -y protobuf-compiler python-pip python3-pip
    cd blackboxprotobuf
    pip2 install -r lib-requirements.txt
    pip3 install -r lib-requirements.txt
    pip2 install -r tests/test-requirements.txt
    pip3 install -r tests/test-requirements.txt
  SHELL
end
