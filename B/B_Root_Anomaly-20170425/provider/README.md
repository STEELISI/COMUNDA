# Tools required for generating labels

The provider (usc-isi-antlab) generated labels for this dataset
requires the `tag` program found in the /tools/usc-isi-antlab/ddos/
directory in the COMUNDA git repository.  Please refer to the
README.md file in that directory for how to create the tool.  The
instructions below describe how to use the tool to generate the
provider given labels for this dataset.


# How to run the tagging code

```
tag -s 1493114000 -e 1493124900 -r <path-to-folder-w-traces> -E lax -q plaza.game981.com 

```