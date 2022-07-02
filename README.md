# k3s-dragon-eggs template 🐉🥚

Some ansible for configuring SUSE-based K3S kubernetes.

OpenSUSE Leap 15.4 is the current OS this is designed for, although it should work on others.
To switch to Ubuntu or RHEL etc, change the ansible zypp to deb etc.

- AES CBC encrypted cluster secrets
- local restrictive firewall rules
- k3s network policy
- wazuh repo add
- rsyslog configuration
- deploy motd

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
```

The default firewalld configuration is rather restrictive. No external API access for k3s when the wall is up.
I like to leave the API blocked, but that isn't always reasonable. The API rule for bottle1 is as follows:

```
firewall-cmd --permanent --zone=public --add-port=6443/tcp 2>/dev/null
```

This set up only has one "worker" node and one service. Add more "bottle2" intenvory items to increase the workers.
The water-bottles.yml can be used to add new nodes to the cluster etc.
