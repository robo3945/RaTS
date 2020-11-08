# RaTS: Ransomware Traces Scanner #

**RaTS** is a **Ransomware Traces Scanner** licensed with **GPL3**.

RaTS does not prevent the Ransomware to do its bad work, but it can **help to find evidences of the existence of Ransomware in your environment** (filesystems).

RaTS is especially useful to periodically monitor network share or external drive to find evidences of the presence of Ransomware. You can run RaTS as a cmd line application or a batch for servers.

## What RaTS can do ##

- find traces of the manifests (TXT or HTML) that Ransomware leaves in the filesystem: around the manifest you can find some crypto stuff...
- find crypto stuff in the file system
- produce outcome CSV files that allow you to analyze the state of your drives (network, NAS, external)
- send the outcome to a configured email

## What RaTS cannot do ##

- prevent the Ransomware encryption

## Platform ##

RaTS is written for Python 3 (>= 3.6) and it works fine in a compiled way for Windows, MacOSX and Linux. We have tested it with PYINSTALLER. 

- Cmd line: *pyinstaller --onefile rats.[osx|win32].pyinstaller* (update the path of the binary in the *.pyinstaller)

## Configuration ##

Configuration of RaTS is made through the config.py and the config.yaml. The former contains the complete configuration while the latter contains only a subset of the parameters. Yaml configuration  was primarily made for the binary execution. 

## Getting started ##

To execute the binaries in Windows 64bit run this command line:

- *rats.win.exe -i  "\\myserver\myshare" -o "./out/fileprefix" -r -v -c ./config.yaml*

## Version history ##

- current version: 1.1

- 3rd version: 1.0b
- second version: 0.9a
- first version: 0.1a