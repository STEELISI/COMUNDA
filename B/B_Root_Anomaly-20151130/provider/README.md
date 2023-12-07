# Tools required for generating labels

The provider (usc-isi-antlab) generated labels for this dataset
requires the `tag` program found in the /tools/usc-isi-antlab/ddos/
directory in the COMUNDA git repository.  Please refer to the
README.md file in that directory for how to create the tool.  The
instructions below describe how to use the tool to generate the
provider given labels for this dataset.


# How to run the tagging code

## For 11/30 attack

```
tag -s 1448866200 -e 1448875160 -r <path-to-folder-w-traces> -q www.336901.com -q www.366901.com
```

## For 12/1 attack

```
tag -s 1448946569 -e 1448950480 -r <path-to-folder-w-traces> -q www.916yy.com
```