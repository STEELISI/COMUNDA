# Tools required for generating labels

The provider (usc-isi-antlab) generated labels for this dataset
requires the `tag` program found in the /tools/usc-isi-antlab/ddos/
directory in the COMUNDA git repository.  Please refer to the
README.md file in that directory for how to create the tool.  The
instructions below describe how to use the tool to generate the
provider given labels for this dataset.


# How to run the tagging code

## For .ari POP

```
tag -s 1567838739 -e 1567838772  -r <path-to-folder-w-traces> -E ari
```

## For .lax POP

```
tag -s 1567838738 -e 1567838773  -r <path-to-folder-w-traces> -E lax
```

## For .mia POP

```
tag -s 1567838739 -e 1567838769 -r <path-to-folder-w-traces> -E mia
```