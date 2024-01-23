# COMUNDA

This project contains labels for datasets released through
<https://comunda.isi.edu>. 

## Label directory structure

All datasets are sub-grouped into letter directories based on the
initial letter of the dataset name.  Within each letter directory is a
directory for datasets that contain labels.  Within each dataset
directory is a subdirectory from the creator of the labels, with
"provider-somenamehere" being a reserved subdirectory name for labels that came
from the dataset provider. 

As an example, labels created by the provider for the
/B_Root_Anomaly-20190907/ dataset can be found in:

    B/B_Root_Anomaly-20190907/provider-uscisiant

When citing labels, please use the label name (omit "provider" if present)
and dataset name. For example provider-uscisiant labels from the above
example could be cited as "uscisiant labels for B_Root_Anomaly-20190907
dataset".

In each subdirectory containing labels, please refer to the specific
README file that describes the associated labels or tools to create
the labels and how to use them.

Each leaf folder relates to a specific dataset. Labels come in many
flavors - per-record or per-event labels. In some cases there will be 
a labeling program or pointers to it, and information needed to
run this program with the original dataset to obtain per-record labels.

## Supporting tools

In some cases, tools have been created to "generate" labels using the
dataset as an input.  These tools, and descriptions about how to
compile and use them, will either be in the dataset subdirectory
itself or may exist in the /tools/ subdirectory, under the label
provider's owner name.  Generic tools like these will be referred to
by specific label subdirectory README files when generic tools or
scripts are to be used for label generation.

As an example, the above /B_Root_Anomaly-20190907/ dataset requires
tools from the "tools/usc-isi-antlab/ddos" directory and are
referenced in the B/B_Root_Anomaly-20190907/provider/README.md file.
These are generic tools that are used for many of the datasets
prefixed with /B_Root_Anomaly-/.
