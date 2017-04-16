# toruk.py

Crowdstrike Falcon Host script for iterating through instances to get alert data, but really can be extended to pull any info within each instance. Primarily designed for multi-tenant customers with more than one instance. (Searches across all instances, which the user has rights to)

## Usage

usage: 
```python
usage: toruk.py [-h] [-a] [-s] [-c CUSTOMER]

optional arguments:
  -h, --help            show this help message and exit
  -a, --alerts          retrieves new alerts
  -s, --systems         retrieves systems information; ss for FULL details in
                        JSON (NOISY!)
  -c CUSTOMER, --customer CUSTOMER
                        cid for specific customer```
You will then be prompted to enter creds and 2fa

sample output:
```
[*] 25 customer instances detected
[*] Searching for new alerts...

Customer A
**********
[!] 2 alert(s) detected!

Customer D
**********
[!] 5 alert(s) detected!

Customer Z
**********
[!] 1 alert(s) detected!

[*] Search complete
```
