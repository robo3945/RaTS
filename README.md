## RaTS: Ransomware Traces Scanner ##

[![License](https://img.shields.io/badge/license-GPL3-green)](https://github.com/robo3945/RaTS/blob/master/LICENSE)
[![Latest Release](https://img.shields.io/badge/release-v1.1.4-blue)](https://github.com/robo3945/RaTS/releases)
[![Build](https://img.shields.io/badge/build-1.6.2-yellowgreen)](https://github.com/robo3945/RaTS/releases/tag/1.6.2)

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

RaTS is written for Python 3 (>= 3.8) and it works fine in a compiled way for Windows, MacOSX and Linux. We have tested it with PYINSTALLER. 

- Cmd line: `pyinstaller --onefile rats.[osx|win32].pyinstaller`

Note: update the path of the binary in the *.pyinstaller

## Configuration ##

Configuration of RaTS is made through the config.py and the config.yaml. The former contains the complete configuration while the latter contains only a subset of the parameters. Yaml configuration  was primarily made for the binary execution. 

## Getting started ##

To execute the binaries in Windows 64bit run this command line:

- `rats.win.exe -i  "myshare" -o "./out/fileprefix" -r -v -c ./config.yaml`

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
-l <dirlistfile>    : a txt file with the directories to scan
-o <outcsv>         : the CSV output file prefix (without the extension)
-x <excl_ext_list>  : file extensions list to exclude from scanning (ex: "jpg,tiff") 
[-e <notify_email>] : where to send the notification
[-k]                : search for crypted files
[-m]                : search for manifest files
[-r]                : recursive search
[-c]                : path for the configuration YAML file
[-v]                : verbose mode (outcome files include all the items detected)
[-h]                : print this help
```

### RaTS rationale ###

Find manifestations of the ransomware activities

```
if file has a bad extension
    'Found bad extension for the file'
else 
    if ext_is_legit and file_size <= MANIFEST_MAX_SIZE
        if filename has a ransomware pattern
            'Found bad filename for the file'
        else 
            if filename has a ransomware pattern in the content
                'Found bad content in the file'
```

Find files with 'probable' crypted content:

```
if file type is NOT well known:
    new content = N_BYTES_2_RAND_CHECK OR content 
    entropy test(new content): http://rosettacode.org/wiki/Entropy#Python:_More_succinct_version in [0,8]
    compression test(new content): len(compressed)/len(uncompressed) in [0,1]
    crypted = entropy test > ENTR_RAND_TH OR compression test > COMPR_RAND_TH
``` 