# DDoS hackathon

This folder contains labeling program for attacks in ddos_hackathon-20200511
dataset. To run this program you will need Perl and nfdump.

## Using the tool for tagging

Tagging tool is `tag_flows.pl`

Run the tool as:

    perl tag_flows.pl path-to-folder-w-netflow path-to-folder-w-attack-files

where path to folder with netflow would be path to one of the days in ddos_hackathon-20200511
dataset, and path to folder with attack files would point to one of the months with labels
for ddos_hackathon-20200511, e.g., ddos_hackathon-20200511/uscisi/may.

The tool produces output of nfdump -o pipe and attaches the `|label` at the end with
`label` being either the letter A (attack) or the letter B (benign). One sample line of
output is shown below:

       2|1589270008|64|1589270398|464|6|0|0|0|282490653|388|0|0|0|169232211|59176|0|0|663|680|24|0|122880|180699136|B

**Note: the tool also needs maptags.txt file in this directory**

## Using the tool for data mining

Data mining tool will produce vectors that you can use for the machine learning example in our documentation.
Note that the tool is very straightforward, and just mines the total number of packets per second per destination
for various types of traffic that also appear in attacks. It is for demonstration purposes and probably needs
much more sophistication to produce data useful in research.

The data mining tool is `mine_features.pl`

Run the tool as:

    perl mine_features.pl file-w-labeled-netflow num-samples

where path to file with labeled netflow would be path to the output of tag_flows.pl
and num-samples would be the number of samples we want to get per A and B category. For example,
choosing 100 samples intends to produce 100 flows tagged as benign (B) and 100 flows
tagged as attack (A). Actually, we produce somewhat lower numbers for benign flows, because
we want to discount the influence of flows that produce very little traffic (vectors are almost
all filled with zeros). How much lower depends on the traffic you are analyzing. It would be
good to run the tool once on a small sample of traffic, see how much lower the output is
than what is intended and scale up your input to the code (num-samples) accordingly.

The tool produces a csv file with vectors where each element of the vector is the total number of
pkts in that second received by a given destination and matching a given traffic type
(e.g., DNS replies) that could be misused for attack. Last element of the vector is label, B-benign
or A-attack. 

**Note: the tool also needs maptags.txt file in this directory**