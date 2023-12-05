# B-Root Anomalies

This folder contains labeling program for B-Root anomalies dataset.
Run:
```
make
```
to create `tag` executable. There are
several folders, containing information on how to use `tag` executable
with the original data to produce record-level tags.
The record-level labels look like:
```
recordID label
```
where recordID looks like:
```
timestamp-sourceIP-sourceport-destIP-destport
```
and label can be A (attack) or B (benign)