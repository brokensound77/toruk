# toruk.py

Crowdstrike Falcon Host script for iterating through instances to get alert data and system information. Can easily be extended to pull any info within each instance. Primarily designed for multi-tenant customers with more than one instance. (Searches across all instances, which the user has rights to)

## Usage

usage: 
```
usage: toruk.py [-h] [-a] [-s] [-i INSTANCE] [-o OUTFILE] [-c CONFIG_FILE]
                [-l {1,2,3,4,5,6,7,8,9,10,11,12}]

optional arguments:
  -h, --help            show this help message and exit
  -a, --alerts          retrieves new alerts
  -s, --systems         retrieves systems information; ss for FULL details in
                        JSON (NOISY!)
  -i INSTANCE, --instance INSTANCE
                        cid for specific customer instance
  -o OUTFILE, --outfile OUTFILE
                        write output to the selected file, rather than to
                        stdout
  -c CONFIG_FILE, --config-file CONFIG_FILE
                        select a config file with user credentials
  -l {1,2,3,4,5,6,7,8,9,10,11,12}, --loop {1,2,3,4,5,6,7,8,9,10,11,12}
                        runs toruk in a loop, for the number of hours passed,
                        running every 10 minutes
```
You will then be prompted to enter creds and 2fa

sample output:
```
python toruk.py -a

<authentication removed>

[*] 25 customer instances detected
[*] Performing search...

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

```
python toruk.py -s

<authentication removed>

[*] 3 customer instances detected
[*] Performing search...

Joe's Widgets
*************
Hosts                                              Last Seen
-----                                              ---------
12345e-web                                         2017-04-16T09:49:54Z
145gt5-db7                                         2017-04-16T09:48:08Z
4asr47-Db1                                         2017-04-16T09:47:46Z
4avs54-APP3                                        2017-04-16T09:47:06Z
abcd21-Db6                                         2017-04-16T09:46:37Z
123a47-db2                                         2017-04-16T09:44:45Z
asas85-web                                         2017-04-16T09:44:35Z
asfs43-web                                         2017-04-01T09:45:44Z
4asr47-Db1                                         2017-04-16T09:47:46Z
4avs54-APP3                                        2017-04-16T09:47:06Z
abcd21-Db6                                         2017-04-16T09:46:37Z
123a47-db2                                         2017-04-16T09:44:45Z

Workers United
**************
Hosts                                              Last Seen
-----                                              ---------
12345e-web                                         2017-04-16T09:49:54Z
145gt5-db7                                         2017-04-16T09:48:08Z
asas85-web                                         2017-04-16T09:44:35Z
asfs43-web                                         2017-04-01T09:45:44Z

Joe's Plumbing Co
*****************
Hosts                                              Last Seen
-----                                              ---------
12345e-web                                         2017-04-16T09:49:54Z
145gt5-db7                                         2017-04-16T09:48:08Z
4asr47-Db1                                         2017-04-16T09:47:46Z
4avs54-APP3                                        2017-04-16T09:47:06Z
abcd21-Db6                                         2017-04-16T09:46:37Z
123a47-db2                                         2017-04-16T09:44:45Z
asas85-web                                         2017-04-16T09:44:35Z
asfs43-web                                         2017-04-01T09:45:44Z

[*] Search complete
```
