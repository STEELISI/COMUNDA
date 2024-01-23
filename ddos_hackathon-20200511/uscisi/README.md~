# Provenance information

Peakflow (now NetScout) appliance was running at FRGP network during
dataset collection and it was generating alerts, which we collected
as well. We pre-filtered these alerts to keep only reflection DDoS
attacks and we have anonymized the alerts to match the dataset
anonymization. Each alert shows the epoch start and stop time of
the attack, and the attack type(s) as reported by Peakflow. The
start time is the actual attack detection time and the stop time
is when the mitigation was stopped.

# Tools required for generating labels

The provider (usc-isi) has produced the tool to use the provided
event labels in this folder and Netflow data from the dataset to
produce per-flow labels (B for benign, A for attack). The tool prints
output of nfdump -o pipe and attaches the label at the end of the line.
The tool can be found in /tools/usc-isi/netflow-ddos/ directory
in the COMUNDA git repository.  Please refer to the
README.md file in that directory for how to run the tool. The
instructions below describe how to use the tool to generate the
provider given labels for this dataset.


# How to run the labeling code

```
perl tag_flows.pl path-to-folder-w-netflow path-to-this-folder
```