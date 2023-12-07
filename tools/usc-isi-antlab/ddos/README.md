# B-Root Anomalies

This folder contains labeling program for anomalies datasets that
start with the prefix /B_Root_anomaly-/.  The `tag` tool in this
directory can be used to analyze each of the dataset's file according
to each dataset's README.md file.

## Creating the tool

Run:
```
make
```
to create `tag` executable. 

## Using the tool

Each dataset contains a README.md file containing information on how
to use `tag` executable with the original data to produce record-level
tags.  The record-level labels that `tag` generated are of the
following format:

    recordID label

where `recordID` is of the form:

    timestamp-sourceIP-sourceport-destIP-destport

and `label` is either the letter A (attack) or the letter B (benign).
