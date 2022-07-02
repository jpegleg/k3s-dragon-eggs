# k3s-dragon-eggs template 🐉🥚

Some ansible for configuring SUSE-based K3S kubernetes.

OpenSUSE Leap 15.4 is the current OS this is designed for, although it should work on others.
To switch to Ubuntu or RHEL etc, change the ansible zypp to deb etc.

- AES CBC encrypted cluster secrets
- blocked egress for service container
- k3s network policy
- wazuh repo add
- rsyslog configuration
- deploy motd
- use calico CNI instead of flannel and apply calico eBPF dataplane 
- install helm on the control plane node
- apply tetragon tracing to the cluster via helm chart
- use calico networking for host firewall rules



## Adjusting and using the template

To start setting it up, we'll need to set the rsyslog host in the files/rsyslog.conf
While this could be a jinja2 template, I don't expect your rsyslog host will change much so setting it before use
is fine and has less configuration files.

```
sed -i 's/SETMETOTHELOGGINGHOST/blah.blah.blah.yourlogginghost/g' files/rsyslog.conf
```

The example `blah.blah.blah.yourlogginghost` would be whatever your wazuh/rsyslog server IP address is.

There is a wazuh agent repo set up in fire-bottle.yml play, but the agent registration is not in there.
The agent registration can be done before the eggs hatch (no network obstacles) via the method in the wazuh documentation:

```
WAZUH_MANAGER="blah.blah.blah.yourlogginghost" zypper install wazuh-agent
```

If you don't want to use a centralized logging/wazuh host, skip fire-bottle.yml.


#### The container image

The `dragon-network.yml` file is a kubernetes manifest. It contains a deployment for a container locally imported and never pulled named `localhost/pki3`. This container is not imported in the template. An example of the import (done on each node):

```
k3s ctr image import pki3.tgz
unpacking localhost/pki3:latest (sha256:3ca374e62f69fd5b9dd6fe2146c859b00827839632fbf03a91b4abcf014c5213)...done

```

This local importing could be replaced by a remote or local registry etc.


#### Nodes

The playbooks are designed for only one control plane node set as `bottle1` in the ansible inventory (hosts.ini in the samples). 
The `bottle2` category is the workers and we can have as many of them as we like, although it is possible that the token expires before we finish the playbook etc. Increase ansible threads or otherwise adjust for larger worker pools.


### Example flow of playbooks

```
# The set-bottles.yml playbook installs some packages and sets the message-of-the-day file /etc/motd.
# This playbook also removes firewalld! The networking and firewalling is to be done with Calico, see dragon-network.yml
# as applied via flight.yml ansible playbook.
anisble-playbook -u root -i hosts.ini set-bottles.yml

# The fire-bottles.yml playbook adds the wazuh 4 repository to bottle1 and bottle2, 
# as well as the gpg signing key, sets an rsyslog.conf, and refreshes zypper.
anisble-playbook -u root -i hosts.ini fire-bottles.yml

# Do any wazuh agent registration here before water-bottles.yml and after fire-bottles.yml.
anisble-playbook -u root -i hosts.ini water-bottles.yml

# The sharpen-claws.yml needs to be applied after the calico pods are all up and ready to go.
# That might take a little while. Go visit the bottle1 and k3s kubectl get pods -A and make sure the calico-* pods are up first.
ansible-playbook -u root -i hosts.ini sharpen-claws.yml

# The hatch-eggs.yml playbook applies files/dragon-network.yml manifest to the cluster via bottle1.
# Ensure the manifest makes sense for your usage and that the 
# container images are imported or otherwise available.
anisble-playbook -u root -i hosts.ini hatch-eggs.yml

# The local firewalling via calico:
anisble-playbook -u root -i hosts.ini flight.yml

```


#### calico eBPF features

It seems that further calico features like the wireguard eBPF may break k3s. As of now I'm leaving out wireguard and DSR for that reason. We'll continue trying to get hose working in k3s successfully.

There is also currently a "bug" with tetragon where some values are populated with null strings:

`"name":"\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000"`

See https://github.com/cilium/tetragon/issues/193 regarding more on the tetragon behavior.

