# toruk

Crowdstrike Falcon Host script for iterating through instances to get alert data and system information. Can easily be extended to pull any info within each instance. Primarily designed for multi-tenant customers with more than one instance. (Searches across all instances, which the user has rights to)

```
                                                                                             `/`
                                                                                           -/-.
                                                                                        `:o+.:
                                                                                      `+s.+/o
                                                                                     /hs+s/d`
     .                                                                            `/o+`so/--
     --   `:                                                                    -oy- +++ s/
      +-   +.                                                                `:osooo+o/+`h`            `
      -+-` ./`                                                             -/oo+/++++sdso-         .:+y-
       +ss. +/`                                                         `/ssso++++oyho:`      `--:s///`
       `hmm-.o:                                                       .oyssso++oss+-`  `.-/+soo:os//`
        `omd.+h:                                                    .oyysssyys+:...:+ossoo++s/::oo.
         `+dh-dm. .                                     ``        -syyyyso/--:+oyyyyso++///+s+:y:
          `ody/No`/.                                    `.-:    -shysoo/+osyyyssssossssssooss+-`
           `odsyy os-                                      /s`-oyysssyyhhhyyyssoo+++/:-.....---..:--/:
            `odyh`yNm-                                    -hNhhhysoosso/::::::::://///+osyy-/++:od+/-`
             `odyo+mm+                               `:+sdmNNmmdhhyyyyssssssssoooo++++++oh/-/oo+:.`
              `ohdmmd.                             `sddhdddhyhhhhhddddhsoo+ooooo++oooooosh+:-.`
               `+hmd++ooyyo        .              `oNmdddyyysssssssysyyhddddddhyysso+///:-.
               .:+shdmmmmmm`   `.:os.             /dNmddhhyyyyyssssossssssyyyyyhhhyyhhhdmd-
               +- `:yNdmmmN+:+:::::.            `+hmmmmdddddhyyyssssssssssssssssssssoosyh-
               .    .sddmmNh+`                 .odNNmmmddddddddhhyyyysssssssssssssooooyh.
                     `ohmdmmh`                .smmNmmmmmddhdddhhhhhhhysssssssoooooooshs.
                    `:-oddmdNh`             `/ymdmNmddddhyysyyhhyyyyyhhhyssssooooooyy/`
                   ./:sysyyhdmy.          ./hmdmmNmddhhhhhyysssyyhhysssyhhhysooosys:`
                  `shNdmmmmmmmhs-`     `-oydmmmNNmdddhhhhhhyyyysssyyyysssssyyhyyo-
               .:sdmdddysosyddmmdo+++osydddmNmmNmmdddddhyyyyhyyssssssyhyyyyyo/-`
       ``.-:/+sdNmNms:..` ``:sdmmmmNNNmmmmmNNNNmdddddhhdhhyyyyyyysyyyyyho:-`
     .--:/+sydNdhyNs`        /ddhhyhdhdmmNNNNmddmmddhhyyhhhhyyyhyys+-.`
      `-/oshNNmdddNs-        sydhhmyhdysydmmmdddddyyyyhhyhddhyo/.`
       `/hmNmmoshMmy+`       /yhhhhhhdhysyhdddhhdhysssossshs:`
         /o/-. smNhs+:       /myhhddmdhyhyyyhhhyyssooooossssso:.
              .dNhs+/:. `/+:-:dhdhdmddhyssyyssysooooooooosssssss-
              `++:-.`..`/hhddhhdhymmdddhssoo+/++oooooooosso/-.`
                       `ohydddhdhmNhhhdhhhho+///++oooos+-`
                        +hyd-/shyydddmddhhhyso+/++ooso.
                        .yyh  `+ydddhhhhhhdhyyso+ooys
                   -/.   :hy .sddhsoyhhhhhhdhhhysosh.
                 `///oo` `sy`smdh+  ./ssyyyhhhhhysoy
                    `+my-`+d.hdhy.    `/syyyyyyyyssy-
                      .hhyhh-hdy-       .syyhhyyyyyys
                       `o   -dh.         .ohhhhoyhyyy/
                        `   .ds            /yhh-`:oyyy:
                            -do             `ohh-  -osy+`
                          `:yh:               -sh+`  `:sy+`
                        `/yd/                   :yho.   -oy+`
                       :shd/                      -+y+.   `:s+:`
                     .++.y o:                        -oo-`   `:o+.
                     +- s-  /                           -+/.    `:+:
                        ``                                 .//-    ./:
                                                              .::.   `-



              **********************************************************
                  ______   ______     ______     __  __     __  __
                 /\__  _\ /\  __ \   /\  == \   /\ \/\ \   /\ \/ /
                 \/_/\ \/ \ \ \/\ \  \ \  __<   \ \ \_\ \  \ \  _"-.
                    \ \_\  \ \_____\  \ \_\ \_\  \ \_____\  \ \_\ \_\
                     \/_/   \/_____/   \/_/ /_/   \/_____/   \/_/\/_/


                      ***** F a l c o n   T o o l   S u i t e *****
                                        zeroex00
              **********************************************************
```

## Setup

download and unzip or git clone

```
cd toruk-master
pip install .
toruk -a
```
OR
```
cd toruk-master/toruk
python toruk -a
```


## Usage

```
usage: toruk.py [-h] [-a] [-s] [-i INSTANCE] [-o OUTFILE] [-c CONFIG_FILE]
                [-l {1,2,3,4,5,6,7,8,9,10,11,12}] [-f FREQUENCY] [-q]

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
                        runs toruk in a loop, for the number of hours passed
  -f FREQUENCY, --frequency FREQUENCY
                        frequency (in minutes) for the loop to resume
  -q, --quiet           suppresses errors from alert retrieval failures
```
You will then be prompted to enter creds and 2fa

## sample output:

### Alerts
```
python toruk.py -a -l 1 -c /location/of/config.cfg
.
.
[*] Credentials read from config file
[$] Enter FH 2FA: 123456
[*] 201 customer instances detected
[*] Performing search (11:24:15L)...
[*] ********************************
[!] Low alert on Joes-Desktop for suspicious_activity (2017-07-20T13:11:08Z)!
----> Joe's Widget Company
[!] Low alert on Martha-Laptop for suspicious_activity (2017-07-20T14:10:12Z)!
----> Workers United
[*] Search complete (10:16:17L)
[-] Sleeping for 1 minute(s)
```

### System Info
```
python toruk.py -s -c /location/of/config.cfg
.
.
[*] Credentials read from config file
[$] Enter FH 2FA: 555777
[*] 500 customer instances detected
[*] Performing search (01:14:29L)...

Joe's Widgets                         
=============                         
Hosts                                 Operating System          Public IP       Last Seen
-----                                 ----------------          ---------       ---------
12345e-web                            Windows Server 2012 R2    50.123.456.20   2017-04-16T09:49:54Z
145gt5-db7                            Windows Server 2012 R2    50.123.456.21   2017-04-16T09:48:08Z
4asr47-Db1                            Windows Server 2012 R2    50.123.456.202  2017-04-16T09:47:46Z
4avs54-APP3                           Windows Server 2012 R2    50.123.45.93    2017-04-16T09:47:06Z
abcd21-Db6                            Windows Server 2012 R2    50.123.45.94    2017-04-16T09:46:37Z
123a47-db2                            Windows Server 2012 R2    50.123.45.205   2017-04-16T09:44:45Z
asas85-web                            Windows Server 2012 R2    50.123.45.96    2017-04-16T09:44:35Z
asfs43-web                            Windows Server 2012 R2    50.123.456.177  2017-04-01T09:45:44Z
4asr47-Db1                            Windows Server 2012 R2    50.123.456.88   2017-04-16T09:47:46Z
4avs54-APP3                           Windows Server 2012 R2    50.123.45.209   2017-04-16T09:47:06Z
abcd21-Db6                            Windows Server 2012 R2    50.123.45.210   2017-04-16T09:46:37Z
123a47-db2                            Windows Server 2012 R2    50.123.456.11   2017-04-16T09:44:45Z
                                      
Workers United                        
==============                        
Hosts                                 Operating System          Public IP       Last Seen
-----                                 ----------------          ---------       ---------
asas85-web                            Windows Server 2012 R2    50.123.45.96    2017-04-16T09:44:35Z
asfs43-web                            Windows Server 2012 R2    50.123.456.177  2017-04-01T09:45:44Z
4asr47-Db1                            Windows Server 2012 R2    50.123.456.88   2017-04-16T09:47:46Z
4avs54-APP3                           Windows Server 2012 R2    50.123.45.209   2017-04-16T09:47:06Z
                                                                            
Joe's Plumbing Co                     
=================                     
Hosts                                 Operating System          Public IP       Last Seen
-----                                 ----------------          ---------       ---------
145gt5-db7                            Windows Server 2012 R2    50.123.456.21   2017-04-16T09:48:08Z
4asr47-Db1                            Windows Server 2012 R2    50.123.456.202  2017-04-16T09:47:46Z
4avs54-APP3                           Windows Server 2012 R2    50.123.45.93    2017-04-16T09:47:06Z
abcd21-Db6                            Windows Server 2012 R2    50.123.45.94    2017-04-16T09:46:37Z
123a47-db2                            Windows Server 2012 R2    50.123.45.205   2017-04-16T09:44:45Z
asas85-web                            Windows Server 2012 R2    50.123.45.96    2017-04-16T09:44:35Z
asfs43-web                            Windows Server 2012 R2    50.123.456.177  2017-04-01T09:45:44Z
4asr47-Db1                            Windows Server 2012 R2    50.123.456.88   2017-04-16T09:47:46Z
                                      
[*] Search complete (01:19:29L)
```

## Detailed Usage

### Config File

```
toruk -c path/to/config.cfg
```

### Configuration File

Usage of all fields within the config file are optional. Instructions for setting up for use with OTP can be found in the [sample](https://github.com/brokensound77/toruk/blob/master/toruk/sample-toruk-cfg.cfg) config file.

Updating the `ignore` field with comma (no space) separated CID's will force toruk to skip over those instances

ex:

config file:

`ignore=1234567890abcdef01234567890abcde,12abc67890abcdef01234abc890abcde`

```
toruk -c /path/to/config.cfg
```

### Detailed Alerts

`toruk -ad`

```
[!] NEW Bob's Widget Company - High alert on BOB-W-12-1 for NGAV (2017-10-12T10:20:10Z)!
                cid: abcd123aceae439da8559b066cdef321 aid: cd7d0daabcdef77c45bb49b887654321
    SYSTEM INFO:
           username: bob.widgeter (S-1-5-21-1232980321-2341652234-1233843123-1004)
                 os: Windows Server 2008 R2
        description: Server
             domain: Widget.Widget
                 ou: [u'Widget', u'Servers']
         victim IPs:
                private: 10.1.2.34
                 public: 123.45.67.89
    ALERT INFO:
           filename: SuspectFile.exe
             hashes:
                sha256: abc12365de31ca6adf41d7e1e91f50daabcdb48966a56509c2421d123dcdef77
                   md5: abcdef6bd89a11a03846f396dcd12345
            cmdline: "C:\Windows\System32\LegitFolder\SuspectFile.exe"
    ALERT PARENT INFO:
            cmdline: C:\Windows\system32\svchost.exe -k netsvcs
             hashes:
                sha256: 11122234565c33a47baa3ddfa089fad17bc8e362f21e835d7123456789abcdef
                   md5: ab436cd5e24105b35e986c0987654321
```

### Status

Can specify one or two statuses to search for: 'new' or 'in_progress'

`toruk -a --status new in_progress`

### Whitelist

If Falcon Host is failing to implement the instance whitelist policy (common occurrence) then the whitelist is pulled, 
verified, and all matching alerts marked as false positive

`toruk -a -wl`


## Tools

standalone scripts / tools

### audit_falcon

```
usage: audit_falcon_policy.py [-h] [-i INSTANCE] [-c CONFIG_FILE] [-csv CSV]

Audit policies of all customers

optional arguments:
  -h, --help            show this help message and exit
  -i INSTANCE, --instance INSTANCE
                        cid for specific customer instance
  -c CONFIG_FILE, --config-file CONFIG_FILE
                        select a config file with user credentials
  -csv CSV              output to specified csv file
  ```
