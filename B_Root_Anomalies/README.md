# Installation

You will need `libpcap-dev` installed. Afterwards, running `make` will produce
executables tag and stats. Stats uses libpcap to read relevant data from
pcap files. It only reads packets to port 53 (this can be changed by changing
filter options in stats.cc).

# Running

Run `tag` with required parameters on a folder containing B-Root-Anomaly files
to tag attack and legitimate traffic. Tagging only occurs during attack period
(between `starttime` and `endtime` parameters). If queryname parameter is present
queries that are malformed or that contain given queryname as substring are
being tagged as attack. If you specify `-A` option then all other traffic from
sources participating in attack is also going to be tagged as attack (e.g., TCP
SYN and ACK packets). If queryname parameter is not present, then all malformed
queries and all zero-name queries (e.g., queries for NS record for ".") will
also be tagged as attack.

Output is comprised of `recordID (timestamp-sourceIP-sourceport-destIP-destport)`
and `B` for "benign", `A` for "attack".

Suggested parameters for tag are given in each subfolder for the specific
attack. We have also provided the output of the tagging process in the same
subfolder (`.tag` files).