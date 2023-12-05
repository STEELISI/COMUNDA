# Tools required for generating labels

The provider (usc-isi-antlab) generated labels for this dataset
requires the `tag` program found in the /tools/usc-isi-antlab/ddos/
directory in the COMUNDA git repository.  Please refer to the
README.md file in that directory for how to create the tool.  The
instructions below describe how to use the tool to generate the
provider given labels for this dataset.


# How to run the tagging code

```
tag -s 1466895600 -e 1466987100 -r <path-to-folder-w-traces>
```
You may need to run this for the folders on 25th and 26th separately.