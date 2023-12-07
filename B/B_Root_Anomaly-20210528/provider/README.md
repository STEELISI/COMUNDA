# Tools required for generating labels

The provider (usc-isi-antlab) generated labels for this dataset
requires the `tag` program found in the /tools/usc-isi-antlab/ddos/
directory in the COMUNDA git repository.  Please refer to the
README.md file in that directory for how to create the tool.  The
instructions below describe how to use the tool to generate the
provider given labels for this dataset.


# How to run the tagging code

## For .ams POP

```
tag -s 1622169357 -e 1622169441 -r <path-to-folder-w-traces> -E ams
```

## For .ari POP

```
tag -s 1622169357 -e 1622169422 -r <path-to-folder-w-traces> -E ari
```

## For .lax POP

```
tag -s 1622169357 -e 1622169608 -r <path-to-folder-w-traces> -E lax
```

## For .iad POP

```
tag -s 1622169357 -e 1622169414 -r <path-to-folder-w-traces> -E iad
```

## For .mia POP

```
tag -s 1622169357 -e 1622169487 -r <path-to-folder-w-traces> -E mia
```


