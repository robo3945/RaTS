## RaTS: Ransomware Traces Scanner ##

[![License](https://img.shields.io/badge/license-GPL3-green)](https://github.com/robo3945/RaTS/blob/master/LICENSE)
[![Build](https://img.shields.io/badge/build-1.7.2b-yellowgreen)](https://github.com/robo3945/RaTS/releases/tag/1.7.2b)

**RaTS** is a **Ransomware Traces Scanner** licensed with **GPL3**.

RaTS does not prevent the Ransomware to do its bad work, but it can **help to find evidences of the existence of Ransomware in your environment** (filesystems).

RaTS is especially useful to periodically monitor network share or external drive to find evidences of the presence of Ransomware. You can run RaTS as a cmd line application or a batch for servers.

### What RaTS can do ###

- it finds traces of the manifests (TXT or HTML) that Ransomware leaves in the filesystem: around the manifest you can find some crypto stuff.
- it finds crypto stuff in the file system
- it makes an outcome CSV file that allow you to analyze the state of your drives (network, NAS, external)
- it sends the outcome to a configured email

### What RaTS cannot do ###

- it does not prevent the Ransomware encryption
- it does not make a live analysis

## Platform ##

RaTS is written for Python 3 (>= 3.8) and it works fine in a compiled way for Windows, MacOSX and Linux. 

## Configuration ##

Configuration of RaTS is made through the config.py and the config.yaml. The former contains the complete configuration while the latter contains only a subset of the parameters. Yaml configuration  was primarily made for the binary execution. 

## Getting started ##

To execute the sources run this command line:

1. Make sure you have Python3
2. Checkout the project
    `git clone https://github.com/robo3945/RaTS.git && cd RaTS`
3. Install the requirements with pip for Python3
    `pip3 install -r requirements.txt`
4. Execute the script with **Python3**
    `python3 rats.py -h`

### Help ###

```
RaTS - v. x.x.x
Directories scan: rats.py -i <inputdir> | -l <dirlistfile> -o <outcsv> [-k|-m] [-e <notify_email>] [-r] [-h] [-c] [-v]

Single file scan: rats.py -f <file> [-k|-m] [-e <notify_email>] [-h] [-c] [-v]

-f <file>           : file to scan
-i <inputdir>       : the starting directory
[-l <dirlistfile>]  : txt file with the directories to include in the scan
[-z <dirlistfile>]  : txt file with the directories to exclude from the scan
-o <outcsv>         : the CSV output file prefix (without the extension)
[-x <excl_ext_list>]: file extensions list to exclude from scanning (ex: "jpg,tiff") 
[-e <notify_email>] : where to send the notification
[-k]                : search for crypted files
[-t]                : crypto engine with argument "all","entropy", "compression", "monobit" (*)
[-m]                : search for manifest files
[-r]                : recursive search
[-c]                : path for the configuration YAML file
[-v]                : verbose mode (outcome files include all the items detected)
[-h]                : print this help

(*) "all" means that the randomness test are all executed for every file
```
