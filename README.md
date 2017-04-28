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

## Usage

```
usage: toruk.py [-h] [-a] [-s] [-i INSTANCE] [-o OUTFILE] [-c CONFIG_FILE]
                [-l {1,2,3,4,5,6,7,8,9,10,11,12}]

optional arguments:
  -h, --help            show this help message and exit
  -a, --alerts          retrieves new alerts
  -s, --systems         retrieves systems information; ss for FULL details in JSON (NOISY!)
  -i INSTANCE, --instance INSTANCE
                        cid for specific customer instance
  -o OUTFILE, --outfile OUTFILE
                        write output to the selected file, rather than to stdout
  -c CONFIG_FILE, --config-file CONFIG_FILE
                        select a config file with user credentials
  -l {1,2,3,4,5,6,7,8,9,10,11,12}, --loop {1,2,3,4,5,6,7,8,9,10,11,12}
                        runs toruk in a loop, for the number of hours passed, running every minute
```
You will then be prompted to enter creds and 2fa

## sample output:

### Alerts
```
python toruk.py -a -c /location/of/config.cfg
.
.
[*] Credentials read from config file
[$] Enter FH 2FA: 123456
[*] 500 customer instances detected
[*] Performing search (01:10:41L)...
Customer A
**********
[!] 2 alert(s) detected!

Customer D
**********
[!] 5 alert(s) detected!

Customer Z
**********
[!] 1 alert(s) detected!

[*] Search complete (01:12:58L)
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
*************                         
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
**************                        
Hosts                                 Operating System          Public IP       Last Seen
-----                                 ----------------          ---------       ---------
asas85-web                            Windows Server 2012 R2    50.123.45.96    2017-04-16T09:44:35Z
asfs43-web                            Windows Server 2012 R2    50.123.456.177  2017-04-01T09:45:44Z
4asr47-Db1                            Windows Server 2012 R2    50.123.456.88   2017-04-16T09:47:46Z
4avs54-APP3                           Windows Server 2012 R2    50.123.45.209   2017-04-16T09:47:06Z
                                                                            
Joe's Plumbing Co                     
*****************                     
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
