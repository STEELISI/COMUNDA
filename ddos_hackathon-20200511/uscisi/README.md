# Provenance information

We (USC/ISI) infer and report the actual start and stop of alleged attack
flows that match Peakflow alerts from ddos_hackathon-20200511/peakflow
directory. These times were established by monitoring all traffic of a
given type to the alleged attack target. We monitor traffic per alleged
attack type, e.g., to detect DNSAmplification attacks we would monitor
all traffic to the alleged target from source port 53. We monitor number of flows,
number of bytes and number of unique sources per second. We signal attack start
when all three of these quantities show a sudden increase, as measured by CUSUM being >5.
We signal end of attack when CUSUM values all fall below 5. We also require that
reverse flows (from alleged target to the sources of traffic flows) do not appear
anomalous (CUSUM values in reverse direction are below 5). This rules out
self-inflicted attacks, e.g., when the alleged target scans a lot of DNS servers, which
then reply back to the target. Attack data is represented as epoch start and stop
time of the attack and the attack type(s). This format matches the format
of Peakflow labels in ddos_hackathon-20200511/peakflow directory

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