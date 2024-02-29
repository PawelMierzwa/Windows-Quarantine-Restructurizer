# Windows Quarantine Restructurizer/Analyzer
Unpacks archive with quarantine files and recreates the original file structure of the Windows quarantine folder  
After the restructurizing is done, the script decodes the files and writes out the quarantined files' information  
Optionally dump the machine info and the actual quarantined files  

This project is designed to work with file dumps of the Windows Quarantine from EDR solutions, 
but it can be slightly changed to work in other solutions for sure.

## Options:
Flag | Full flag | Param | Definition
--- | --- | --- | --- 
-p | --password | PASSWORD | Archive password
-o | --output | OUTPUT_PATH | Output files' path
-m | --mode | MODE |  Hash type to show (md5, sha1, sha256)
-d | --dump | | Dump the recovered files
-i | --info | | Dump system information of the quarantine owner

## Prerequisites:
`pip install prettytable pyzipper isodate`
* [prettytable](https://pypi.org/project/prettytable)
* [pyzipper](https://pypi.org/project/pyzipper)
* [isodate](https://pypi.org/project/isodate)  

---
### Credits:
* [@CyberGoatherder](https://github.com/CyberGoatherder/WinDefReleaser)
* [@knez](https://github.com/knez/defender-dump)
