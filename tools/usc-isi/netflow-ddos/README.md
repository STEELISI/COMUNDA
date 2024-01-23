# DDoS hackathon

This folder contains labeling program for attacks in ddos_hackathon-20200511
dataset. To run this program you will need Perl and nfdump.

## Using the tool

Run the tool as:

    perl tag_flows.pl path-to-folder-w-netflow path-to-folder-w-attack-files

where path to folder with netflow would be path to one of the days in ddos_hackathon-20200511
dataset, and path to folder with attack files would point to one of the months with labels
for ddos_hackathon-20200511, e.g., ddos_hackathon-20200511/uscisi/may.

The tool produces output of nfdump -o pipe and attaches the `|label` at the end with
`label` being either the letter A (attack) or the letter B (benign). One sample line of
output is shown below:

       2|1589270008|64|1589270398|464|6|0|0|0|282490653|388|0|0|0|169232211|59176|0|0|663|680|24|0|122880|180699136|B