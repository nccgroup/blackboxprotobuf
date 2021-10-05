# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/impish64"

  config.vm.synced_folder "./", "/vagrant", disabled: true

  config.vm.synced_folder "./", "/home/vagrant/blackboxprotobuf", type: "rsync"
  config.vm.provision "shell", inline: <<-SHELL
    echo "export PATH=/home/vagrant/.local/bin/:$PATH" >> /home/vagrant/.bashrc
    sudo apt-get update
    sudo apt-get install -y protobuf-compiler python2 python3-pip
    pip3 install poetry
    cd blackboxprotobuf/lib
    poetry env use python2 && poetry install --no-root
    poetry env use python3 && poetry install --no-root
  SHELL
end
