# k3s-dragon-eggs template 🐉🥚

Some ansible for configuring SUSE-based K3S kubernetes.

OpenSUSE Leap 15.4 is the current OS this is designed for, although it should work on others.
To switch to Ubuntu or RHEL etc, change the ansible zypp to deb etc.

- AES CBC encrypted cluster secrets
- local restrictive ingress firewall rules
- blocked egress for service container
- k3s network policy
- wazuh repo add
- rsyslog configuration
- deploy motd
- use calico CNI instead of flannel and apply calico eBPF dataplane with DSR and wireguard

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

### Example flow of playbooks

```
# The set-bottles.yml playbook installs some packages and sets the message-of-the-day file /etc/motd.
# This playbook also stops firewalld to allow configuration and remote registrations temporarily.
anisble-playbook -u root -i hosts.ini set-bottles.yml
# The fire-bottles.yml playbook adds the wazuh 4 repository to bottle1 and bottle2, 
# as well as the gpg signing key, sets an rsyslog.conf, and refreshes zypper.
anisble-playbook -u root -i hosts.ini fire-bottles.yml
# Do any wazuh agent registration here before water-bottles.yml and after fire-bottles.yml.
anisble-playbook -u root -i hosts.ini water-bottles.yml
# The hatch-eggs.yml playbook brings firewalld back up and allows port 30311 on the "bottle2" host.
# The hatch-eggs.yml playbook also applies files/dragon-network.yml manifest to the cluster via bottle1.
anisble-playbook -u root -i hosts.ini hatch-eggs.yml
# The sharpen-claws.yml needs to be applied after the calico pods are all up and ready to go.
# That might take a little while. Go visit the bottle1 and k3s kubectl get pods -A and make sure the calico-* pods are up first.
ansible-playbook -u root -i hosts.ini sharpen-claws.yml
```

The default firewalld configuration is rather restrictive on bottle1. No external API access for k3s when the wall is up.
I like to leave the API blocked, but that isn't always reasonable. The API rule for bottle1 is as follows:

```
firewall-cmd --permanent --zone=public --add-port=6443/tcp
```

This set up only has one "worker" node and one service. Add more "bottle2" intenvory items to increase the workers.
The water-bottles.yml can be used to add new nodes to the cluster etc. By default bottle2 hosts are untagged and also
firewalld is disabled. 

#### The container image

The `dragon-network.yml` file is a kubernetes manifest. It contains a deployment for a container locally imported and never pulled named `localhost/pki3`. This container is not imported in the template. An example of the import (done on each node):

```
k3s ctr image import pki3.tgz
unpacking localhost/pki3:latest (sha256:3ca374e62f69fd5b9dd6fe2146c859b00827839632fbf03a91b4abcf014c5213)...done

```

This image is the front-end container for the services. If there are many microservices services, it could be the api gateway type thing, etc.
Alternatively, more deployments are services are created and firewall rules opened up etc. Update the `dragon-network.yml` to contain any additional deployments etc. The design here is a single manifest maintained remotely on the ansible bastion host, the same one that is running the playbooks. It likely would be pulled down to the bastion from a git repo, or otherwise stored however you like. None of that is within scope of this template.

#### Nodes

The playbooks are designed for only one control plane node set as `bottle1` in the ansible inventory (hosts.ini in the samples). 
The `bottle2` category is the workers and we can have as many of them as we like.

Further added control plane nodes can be done as described in the k3s documentation. Workers may be added via the `water-bottles.yml` or separately.

