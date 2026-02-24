# -*- mode: ruby -*-
# vi: set ft=ruby :

require 'yaml'
vars = YAML.load_file 'vars.yml'

Vagrant.configure("2") do |config|

  if Vagrant.has_plugin?("vagrant-vbguest") then
    config.vbguest.auto_update = false
  end

  config.vm.synced_folder ".", "/vagrant"
  config.vm.provision "shell", path: "bootstrap_all.sh"
  config.vm.provision :hosts, :sync_hosts => true

  # attacker
  config.vm.define "attacker" do |node|
    node.vm.box               = vars['shared']['box']
    node.vm.box_check_update  = false
    node.vm.hostname          = "attacker"
    node.vm.network vars['shared']['networktype'] + "_network", ip: vars['shared']['network'] + "0", bridge: "enx24f5a28b44a6"
    node.vm.provider :virtualbox do |v|
      v.name    = "attacker"
      v.memory  = vars['shared']['mem_size']
      v.cpus    = vars['shared']['cpus']
    end      
    node.vm.provision "shell", path: "bootstrap_attacker.sh"
  end

  # vuln
  config.vm.define "vuln" do |node|
    node.vm.box               = vars['shared']['box']
    node.vm.box_check_update  = false
    node.vm.hostname          = "vuln"
    node.vm.network vars['shared']['networktype'] + "_network", ip: vars['shared']['network'] + "1", bridge: "enx24f5a28b44a6"
    node.vm.provider :virtualbox do |v|
      v.name    = "vuln"
      v.memory  = vars['shared']['mem_size']
      v.cpus    = vars['shared']['cpus']
    end      
    node.vm.provision "shell", path: "bootstrap_vuln.sh"
  end

  # novuln
  config.vm.define "novuln" do |node|
    node.vm.box               = vars['shared']['box']
    node.vm.box_check_update  = false
    node.vm.hostname          = "novuln"
    node.vm.network vars['shared']['networktype'] + "_network", ip: vars['shared']['network'] + "2", bridge: "enx24f5a28b44a6"
    node.vm.provider :virtualbox do |v|
      v.name    = "novuln"
      v.memory  = vars['shared']['mem_size']
      v.cpus    = vars['shared']['cpus']
    end
    node.vm.provision "shell", path: "bootstrap_novuln.sh"
  end 

  # Reboot all nodes after provisioning
  config.vm.provision :reload
end