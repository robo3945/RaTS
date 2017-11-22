# RaTS: Ransomware Traces Scanner #

**RaTS** is a **Ransomware Traces Scanner** licensed with **GPL3**.

RaTS does not prevent the Ransomware to do its bad work, but it can **help to find evidences of the existence of Ransomware in your environment** (filesystems).

RaTS is especially useful to periodically monitor network share or external drive to find evidences of the presence of Ransomware. You can configure it as a batch task in a client machine, but the way it works does not fit very well with this use case.

## What RaTS can do ##

- find traces of the manifests (TXT or HTML) that Ransomware leaves in the filesystem: around the manifest you can find some crypto stuff...
- find crypto stuff in the file system
- produce outcome CSV files that allow you to analyze the state of your drives (network, NAS, external)
- send the outcome to a configured email

## What RaTS cannot do ##

- prevent the Ransomware encryption

## Platform ##

RaTS is written for Python 3 (> 3.5) and it works fine in a compiled way for Windows, MacOSX and Linux. We have tested with PYINSTALLER. Cmd line: *pyinstaller -F rmw-checker.py -N rmw-checker.osx*

## Version history ##

first version: 0.9a