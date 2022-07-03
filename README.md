# k3s-dragon-eggs template 🐉🥚

Some ansible for configuring SUSE-based K3S kubernetes.

OpenSUSE Leap 15.4 is the current OS this is designed for, although it should work on others.
To switch to Ubuntu or RHEL etc, change the ansible zypp to deb etc.

- AES CBC encrypted cluster secrets
- restricted ingress and egress on node host and containers
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

The `dragon-manifest.yml` file is a kubernetes manifest. It contains a deployment for a container locally imported and never pulled named `localhost/pki3`. This container is not imported in the template. An example of the import (done on each node):

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
# I do have firewall rules that allow wazuh and syslog, so it could be done later, but makes sense here.
anisble-playbook -u root -i hosts.ini water-bottles.yml

# The sharpen-claws.yml needs to be applied after the calico pods are all up and ready to go.
# That might take a little while. Go visit the bottle1 and k3s kubectl get pods -A and make sure the calico-* pods are up first.
ansible-playbook -u root -i hosts.ini sharpen-claws.yml

# The hatch-eggs.yml playbook applies files/dragon-manifest.yml manifest to the cluster via bottle1.
# Ensure the manifest makes sense for your usage and that the 
# container images are imported or otherwise available.
anisble-playbook -u root -i hosts.ini hatch-eggs.yml

# The local firewalling via calico:
anisble-playbook -u root -i hosts.ini flight.yml

```


#### calico eBPF features

It seems that further calico features like the wireguard eBPF may break k3s. As of now I'm leaving out wireguard and DSR for that reason. We'll continue trying to get those working in k3s successfully.

There is also currently a "bug" with tetragon where some values are populated with null strings:

`"name":"\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000"`

See https://github.com/cilium/tetragon/issues/193 regarding more on the tetragon behavior.

Despite those issues, calico and tetragon still provide great value. The removal of SNAT from calico eBPF dataplane, the global network policy options are very granular and expansive, calico can extend on to many different types of hosts and infrastructure, and the syscall tracing in tetragon are all truly great reasons to run both of them.

## Adjusting the firewall

The default allows access to specific ports defined in `dragon-network.yml` from `192.168.1.0/24`.
Adjust files/dragon-network.yml to include any firewall rules or adjustments needed.

#### Removing network policies and maintenance

The policy blocks non-local traffic by default. With calico enterprise, DNS based policy for the (opensuse) repos can be effectively added. Alternatively, IP addresses can be added in to the egress rules.

I prefer to drop the policy when maintenance is being done. The policies are global network policies and can be removed by calicoctl (with cluster admin auth in place):

```
bottle1:~ # calicoctl get gnp
NAME           
default-deny   
allow-rules  
```

From there, we can `calicoctl delete gnp default-deny` etc, do the zypper updates, then reapply the policies `anisble-playbook -u root -i hosts.ini flight.yml`.

Instead of dropping the policy in an enterprise environment, we might have calico enterprise installed with the DNS based egress out to the internet repo, or alternatively have a local RPM repo that zypper is further configured to use.



#### CICD without an image registry option

While an image registry can be added to the configuration, we can also do CICD via ssh/ansible. Example description:
Have the image built, SBOM constructed, signed, tested, verified, and approved in the CICD, then send the exported image 
tar file out to the nodes and use the ctr image import, then apply the manifests. I rather like having SSH-based CICD
because we can put very strong controls and identity around SSH easily, where as remote registries are a bit more
work to maintain and keep that same level of security. 
Instead of an image registry, a collection of signed and backed up artifacts (image tarballs) can be 
an alternative option.


#### metarc aliases

The calico eBPF dataplane and calicoctl are applied via files/patch-ebpf, deployed to the control plane and executed by sharpen-claws.yml.
The sharpen-claws.yml is needed before the flight.yml can be leveraged as is, because the network policy (firewall) requires calicoctl.

The aliases in https://github.com/jpegleg/metarc for calicoctl are a reference for enabling and disabling various calico eBPF patches.
As mentioned earlier, k3s breaks with some of these patches (calico nodes and apiserver crash and various other issues), so I don't recommend changing the eBPF dataplane much for this build, unless you chose to go without it entirely. The main downsides to removing the eBPF dataplane: NAT will return and microservices won't have original client IP addresses, likely worse network performance, especially when there are several potential layers of services. 

#### microk8s vs k3s

Both microk8s and k3s provide easy pool growth, easy to install and uninstall, and work across many distros and situations.

Microk8s is easier than k3s and works in more situations.
The downside/feature of microk8s is that it is installed via snap, which makes it easy to install on any GNU/linux distro,
but there is some lack of control over the snap itself. Despite the "vendor managed" nature of microk8s, it handles calico better than k3s (uses it by default), and has many ready to use features. When I build microk8s clusters I typically enable wireguard and DSR patches (as seen in the metarc alias' `dsron` and `cwireon`) in addition to the one used here and with k3s `ebpfon`.

K3S has a nice secrets encryption mechanism, also included in this template.
K3S is perhaps easier to customize the API storage.
K3S has some features that are arguably better security practices, including
not setting a control plane IP in the auth token CA ASN1 data.
K3S has a little more control, although still is a "supplied build" of kubernetes.

There are plenty of clusters where I would do something other than microk8s or k3s, 
however both of microk8s and k3s are very easy to use and with that, easy for 
developers to reproduce configurations. Microk8s has an "EKS" configuration
option available that mimics the AWS EKS modules, which can be useful
for constructing individual developer test replicas when EKS is used in production.

Microk8s is easier to add control plane nodes to the cluster, but both microk8s and k3s are easy 
relative to most implementations that are any good.

More "demo" type impelementations like Kind and Minikube are not very good at doing real network
things, so I avoid them in general. Microk8s and k3s can run on small systems and still do
many great networking tasks.

#### Rambling about calico

Regardless of which kubernetes distribution I use, I typically use calico CNI plugin because of
how easy it is to use and optimize: the ability to remote SNAT and preserve client IP addresses
with a single patch while at the same time improving network performance is incredible. 
And calico can extend on to other devices. In this template we set BGP between cluster nodes
and have host-level network rules declared once on the control plane, applying to every labelled
node in the cluster. 

This is the second rule in the template denies all traffic.

```
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: default-deny
spec:
  order: 1
  selector: "all()"
  types:
  - Ingress
  - Egress
```

The way the rules work is that the "order" that is lowest is resolved first. We have a "0" order rule before our deny all rule:

```
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-rules
spec:
  selector: "all()"
  order: 0
  ingress:
  - action: Allow
    protocol: TCP
    source:
      nets:
        - "192.168.1.0/24"
    destination:
      ports: 
        - 22
        - 1514
        - 1515
        - 30311
  - action: Allow
    protocol: ICMP
  egress:
  - action: Allow
    protocol: TCP
    destination:
      nets:
        - "192.168.1.0/24"
      ports:
        - 514
        - 1514
        - 1515
  - action: Allow
    protocol: UDP
    destination:
      ports: 
        - 67
        - 1515
        - 1514
```


The result of this is that "0" resolves "first" in the chain, traffic that matches those rules in our "allow-rules" global network policy resolve, then the "1" rules resolve "second" in the chain, denying everything. The result is that unless explicity defined in "0", the traffic is blocked. 

Read more about calico global network policies here: https://projectcalico.docs.tigera.io/reference/resources/globalnetworkpolicy
