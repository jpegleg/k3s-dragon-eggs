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

The playbooks (and in general k3s) are designed for only one control plane node set as `bottle1` in the ansible inventory (hosts.ini in the samples). 
The `bottle2` category is the workers and we can have as many of them as we like. While the default k3s tokens are long lived at the moment, it is possible that the token expires before we finish the playbook (if the token life is reduced in the bottle1 config etc). Increase ansible threads or otherwise adjust for larger worker pools. There might be a timeout applying the calico manifest after adding the workers, that typically will happen if a calico-node for one of multiple workers is slow starting up. I added a small sleep before the calico apply, feel free to adjust as needed.


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

The calico eBPF dataplane does have a few limitations, but improves performance, removes SNAT, and gives us some interesting options.

The host-level global network policy does not work well with wireguard and/or DSR enabled eBPF dataplane. This template uses global network policy, so we don't want to use those features.


#### Tetragon

Tetragon is a great way to trace activity in a cluster. There is an additional tetragon binary that can be installed to parse the JSON into prettier output for console viewing.

There is also currently a "bug" with tetragon where some values are populated with null strings:

`"name":"\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000"`

See https://github.com/cilium/tetragon/issues/193 regarding more on the tetragon behavior.

Despite those issues, calico and tetragon still provide great value. The removal of SNAT from calico eBPF dataplane, the global network policy options are very granular and expansive, calico can extend on to many different types of hosts and infrastructure, and the syscall tracing in tetragon are all truly great reasons to run both of them.

## Adjusting the firewall

The default allows access to specific ports defined in `dragon-network.yml` from `192.168.1.0/24`.
Adjust files/dragon-network.yml to include any firewall rules or adjustments needed.

#### Removing network policies and maintenance

The policy blocks non-local traffic by default. With calico enterprise, DNS based policy for the (opensuse) repos can be effectively added. Alternatively, IP addresses can be added in to the egress rules.

I prefer to drop the policy when maintenance is being done. The policies are global network policies and can be removed by calicoctl (with cluster admin auth, or networking ServiceAccount auth, in place):

```
bottle1:~ # calicoctl get gnp -o wide
NAME           ORDER   SELECTOR   
allow-rules    0       all()      
default-deny   1       all()      

```

From there, we can `calicoctl delete gnp default-deny` etc, do the zypper updates, then reapply the policies `anisble-playbook -u root -i hosts.ini flight.yml`.

Instead of dropping the policy in an enterprise environment, we might have calico enterprise installed with the DNS based egress out to the internet repo, or alternatively have a local RPM repo that zypper is further configured to use.

#### Adding a role specific rule to the global allow policy

Keeping the global policy simple is optimal. If there is a need for large amounts of variety, we might do microservice specific network policy instead, keeping the global policy as short as is reasonable. With that said, there are often a few general categories of nodes that desire different rules.

An example node role based "allow all egress deny all ingress" rule:

```
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: egressor
spec:
  selector: role == 'workstation'
  order: 0
  types:
  - Ingress
  - Egress
  ingress:
  - action: Deny
  egress:
  - action: Allow

```
With the example added, nodes in the cluster tagged with the role 'workstation' by the control plane have "global" access to anything outbound but nothing inbound... except that we have a rule at the same level "0" that allows specific ports, which will then override the ingress Deny. As long as the global allow and the global deny rules are also included, they will still be in effect in the chain.


#### Using declarative felix configuration

Instead of (or in addition to) patching in the eBPF options for calico, we can use it declaratively in the network manifest like this:

```
apiVersion: projectcalico.org/v3
kind: FelixConfiguration
metadata:
  name: default
spec:
  bpfEnabled: true
  bpfDisableUnprivileged: true
  bpfKubeProxyIptablesCleanupEnabled: true

  
```
Only use the "bpfKubeProxyIptablesCleanupEnabled: true" if kubeproxy is disabled, which it is in the template here currently.
Instead of enabling eBPF like the example above, we might disable eBPF and set netfilter chaining to either Append or Insert:

```
apiVersion: projectcalico.org/v3
kind: FelixConfiguration
metadata:
  name: default
spec:
  bpfEnabled: false
  chainInsertMode: Append
  bpfDisableUnprivileged: true
  
```

The `bpfDisableUnprivileged: true` option is typically default for most linux distros, but might as well declare that we don't want that explicity here since we can.

See more options for Felixconfiguration here: https://projectcalico.docs.tigera.io/reference/resources/felixconfig


Note: sometimes changes to rules will not immediately update a node during runtime. Reboot the node to kick on the modification. 

The kubernetes API 6443 is persistently exposed by default, however requiring authentication. 


#### CICD without an image registry option

While an image registry can be added to the configuration, we can also do CICD via ssh/ansible. Example description:
Have the image built, SBOM constructed, signed, tested, verified, and approved in the CICD, then send the exported image 
tar file out to the nodes and use the ctr image import, then apply the manifests. I rather like having SSH-based CICD
because we can put very strong controls and identity around SSH easily, where as remote registries are a bit more
work to maintain and keep that same level of security. 
Instead of an image registry, a collection of signed and backed up artifacts (image tarballs, along with SBOMs, manifests, and ansible etc) 
can be an alternative option.


#### metarc aliases

The calico eBPF dataplane and calicoctl are applied via files/patch-ebpf, deployed to the control plane and executed by sharpen-claws.yml.
The sharpen-claws.yml is needed before the flight.yml can be leveraged as is, because the network policy (firewall) requires calicoctl.

The aliases in https://github.com/jpegleg/metarc for calicoctl are a reference for enabling and disabling various calico eBPF patches.
As mentioned earlier, k3s breaks with some of these patches (calico nodes and apiserver crash and various other issues), so I don't recommend changing the eBPF dataplane much for this build, unless you chose to go without it entirely. The main downsides to removing the eBPF dataplane: NAT will return and microservices won't have original client IP addresses, likely worse network performance, especially when there are several potential layers of services. 

#### microk8s vs k3s

Both microk8s and k3s provide easy pool growth, easy to install and uninstall, and work across many distros and situations.

See an example microk8s template in https://github.com/jpegleg/storm-reef-clusters
That "storm-reef-clusters" template also has the wireguard and DSR features on and the global network policy off.


Microk8s is easier than k3s and works in more situations.
The downside/feature of microk8s is that it is installed via snap, which makes it easy to install on any GNU/linux distro,
but there is some lack of control over the snap itself. Despite the "vendor managed" nature of microk8s, it handles calico better than k3s (microk8s uses the calico CNI plugin with default install currently, where as with k3s we had to take special install steps), and has many ready to use features. When I build microk8s clusters I typically enable wireguard and DSR patches (as seen in the metarc alias' `dsron` and `cwireon`) in addition to the one used here and with k3s `ebpfon`.

K3S has a nice secrets encryption mechanism, also included in this template.
K3S is perhaps easier to customize the API storage.
K3S has some features that are arguably better security practices, including
not setting a control plane IP in the auth token CA ASN1 data.
K3S has a little more control, although still is a "supplied build" of kubernetes.

There are plenty of clusters where I would do something other than microk8s or k3s, 
however both microk8s and k3s are very easy to use and with that, easy for 
developers to reproduce configurations. Microk8s has an "EKS" configuration
option available that mimics the AWS EKS modules, which can be useful
for constructing individual developer test replicas when EKS is used in production.

Microk8s is easier to add control plane nodes to the cluster.
The sqlite storage in k3s limits it to a single control plane node, although it is possible to use a remote storage and link multiple k3s control plane nodes to it, that is a bit more steps to accomplish.
Microk8s can add control plane nodes as easily as worker nodes. 
Both microk8s and k3s are easy to add worker nodes.

More "demo" type implementations like Kind and Minikube are not very good at doing real network
things, so I avoid them in general. Microk8s and k3s can run on small systems and still can do
many great (accurate and flexible) networking tasks.

#### Rambling about calico

Regardless of which kubernetes distribution I use, I typically use calico CNI plugin because of
how easy it is to use and optimize: the ability to remote SNAT and preserve client IP addresses
with a single patch (or felix manifest) while at the same time improving network performance is incredible. 
And calico can extend on to other devices. In this template we set BGP between cluster nodes
and have host-level network rules declared once on the control plane, applying to every node in the cluster. 

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
      nets:
        - "192.168.1.0/24"
```


The result of this is that "0" resolves "first" in the chain, traffic that matches those rules in our "allow-rules" global network policy resolve, then the "1" rules resolve "second" in the chain, denying everything. The result is that unless explicity defined in "0", the traffic is blocked. 

Read more about calico global network policies here: https://projectcalico.docs.tigera.io/reference/resources/globalnetworkpolicy

#### Adding syslog TLS

The template doesn't include gnutls and syslog over TLS by default.
If the syslog data traverses the internet or untrusted networks, then it should also have TLS applied to it.

Typicall syslog over TLS will be port `10514`, add the appropriate port to the egress rule/s. Example adding it to the existing allow:

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
        - 10514
        - 1514
        - 1515
  - action: Allow
    protocol: UDP
    destination:
      nets:
        - "192.168.1.0/24"

```

On the wazuh/logging host (rsyslog server), ensure it is set up for a TLS syslog listener in the /etc/rsyslog.conf:

```
# make gtls driver the default
$DefaultNetstreamDriver gtls

# certificate files
$DefaultNetstreamDriverCAFile /path/to/contrib/gnutls/ca.pem
$DefaultNetstreamDriverCertFile /path/to/contrib/gnutls/cert.pem
$DefaultNetstreamDriverKeyFile /path/to/contrib/gnutls/key.pem

$ModLoad imtcp # load TCP listener

$InputTCPServerStreamDriverMode 1 # run driver in TLS-only mode
$InputTCPServerStreamDriverAuthMode anon # client is NOT authenticated
$InputTCPServerRun 10514 # start up listener at port 10514
```


And then update the files/rsyslog.conf file used by the clients, removing line 41 and adding:

```
# certificate files - just CA for a client
$DefaultNetstreamDriverCAFile /path/to/contrib/gnutls/ca.pem

# set up the action
$DefaultNetstreamDriver gtls # use gtls netstream driver
$ActionSendStreamDriverMode 1 # require TLS for the connection
$ActionSendStreamDriverAuthMode anon # server is NOT authenticated
*.* @@(o)blah.blah.blah.yourlogginghost:10514 # send (all) messages
```

The playbook `fire-bottles.yml` deploys the rsyslog conf and updates wazuh agent software. To only push the rsyslog conf and restart rsyslog (without updating wazuh), use the rsyslog tag:

```
ansible-playbook -u root -i hosts.inventory fire-bottles.yml --tags rsyslog
```

#### Bypassing this networking

For an adversary or person to bypass the network rules, they must have access to a node as root, un-install k3s (to remove the calico node controller), then either reboot the node or unload the correct eBPF from the kernel manually. This is more challenging than disabling ufw, iptables, or firewalld rules. It is roughly the same difficulty as disabling selinux rules.

Unless rsyslog and wazuh agent are disabled first, then evidence of the tampering is forwarded off to the centralized server, as long as those aspects are utilized.

Alternatively, if the adversary gains control of cluster admin credentials and local network access, then they could potentially modify the network rules that way. Not giving out cluster admin credentials to anything is smart. If credentials to the control plane kubernetes API need to be utilized elsewhere, such as for CICD, create a ServiceAccount that has a very limited scope that doesn't include network, probably can define explicit resources of Deployments only in many cases, perhaps Services. An adversary with a ServiceAcount can still attack and get into the cluster, but the network still traps them in some if the scope is tight. The adversary could bypass the network restrictions with tunneling to and from a LAN network host outside of the cluster, etc.

Additionally to removing then rebooting, there is a potential for timing issues during the start sequence: we can potentially slip outbound for a short moment of time during the boot sequence in some situations. If the policy is dropped for maintenance, slipping out during maintenance could be a possibility. While there could be some fancy timing attacks related to this, rebooting typically isn't going to happen often enough for that to be of much use, but if such a gap is utilized it could be enough for data exfiltration etc.

