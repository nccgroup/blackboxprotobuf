# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "bento/ubuntu-22.04"

  config.vm.synced_folder "./", "/vagrant", disabled: true

  config.vm.synced_folder "./", "/home/vagrant/blackboxprotobuf", type: "rsync"
  #config.vm.synced_folder "./", "/home/vagrant/blackboxprotobuf"
  config.vm.provision "shell", inline: <<-SHELL
    echo "export PATH=/home/vagrant/.local/bin/:$PATH" >> /home/vagrant/.bashrc
    sudo apt-get update
    sudo apt-get install -y protobuf-compiler jython python3-pip python2
    wget https://bootstrap.pypa.io/pip/2.7/get-pip.py -O /tmp/get-pip2.py
    python2 /tmp/get-pip2.py
    python3 -m pip install poetry
    python2 -m pip install virtualenv
  SHELL

  config.vm.provision "shell", privileged: false, inline: <<-SHELL
    cd blackboxprotobuf/lib
    #poetry env use python2 && poetry install --no-root
    poetry env use python3 && poetry install --no-root
    poetry env use python3 && poetry run mypy --install-types
  SHELL
end
