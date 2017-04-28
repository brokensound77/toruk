#!/usr/bin/python
#
# MIT License
# br0k3ns0und

import requests
from getpass import getpass
import json
import argparse
import ConfigParser
import time
# temp for testing
import pprint


pp = pprint.PrettyPrinter(indent=4)
config = ConfigParser.RawConfigParser()
falcon = requests.Session()
parser = argparse.ArgumentParser()
header = {
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US; q=0.7, en; q=0.3',
        'Cache-Control': 'no-cache',
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
        }
FALCON_UNAME = ''
FALCON_PASS = ''


parser.add_argument('-a', '--alerts', action='store_true', help='retrieves new alerts')
parser.add_argument('-s', '--systems', action='count', default=0,
                    help='retrieves systems information; ss for FULL details in JSON (NOISY!)')
parser.add_argument('-i', '--instance', type=str, help='cid for specific customer instance')
parser.add_argument('-o', '--outfile', type=str, help='write output to the selected file, rather than to stdout')
parser.add_argument('-c', '--config-file', type=str, help='select a config file with user credentials')
parser.add_argument('-l', '--loop', type=int, choices=[1,2,3,4,5,6,7,8,9,10,11,12],
                    help='runs toruk in a loop, for the number of hours passed, running every minute')
args = parser.parse_args()


def set_auth():
    global FALCON_UNAME
    global FALCON_PASS
    if args.config_file is not None:
        try:
            config.read(args.config_file)
            FALCON_UNAME = str(config.get('Falconhost', 'username'))
            FALCON_PASS = str(config.get('Falconhost', 'password'))
            print '[*] Credentials read from config file'
        except Exception as e:
            print '[!] Check your config file and rerun the program, exiting...\n'
            exit(2)
    else:
        FALCON_UNAME = raw_input('[$] Enter FH Username (email address): ')
        FALCON_PASS = getpass(prompt='[$] Enter FH Password: ')


def falcon_auth():
    """ Authentication Process """
    falcon.get('https://falcon.crowdstrike.com/login/', headers=header)
    r2 = falcon.post('https://falcon.crowdstrike.com/api2/auth/csrf', headers=header)
    header['X-CSRF-Token'] = r2.json()['csrf_token']
    fh_2fa = raw_input('[$] Enter FH 2FA: ')
    auth_data = {'username': FALCON_UNAME, 'password': FALCON_PASS, '2fa': fh_2fa}
    falcon.post('https://falcon.crowdstrike.com/auth/login', headers=header, data=json.dumps(auth_data))
    falcon.get('https://falcon.crowdstrike.com')


def toruk(alerts, systems, customer_cid, outfile):
    falcon.get('https://falcon.crowdstrike.com')
    r5 = falcon.post('https://falcon.crowdstrike.com/api2/auth/verify', headers=header)
    if r5.status_code != 200:
        falcon_auth()
        r5 = falcon.post('https://falcon.crowdstrike.com/api2/auth/verify', headers=header)
    ########################
    # retrieve customer list
    ########################
    try:
        customer_list = r5.json()['customers']
        header['X-CSRF-Token'] = r5.json()['csrf_token']
    except KeyError:
        print '[!] Check your credentials and rerun the program, exiting...\n'
        exit(2)
    # customer_cid handling (if passed)
    if customer_cid is not None:
        customer_list = [customer_cid]
    ###################################
    print '[*] {0} customer instances detected'.format(len(customer_list))
    print '[*] Performing search ({0})...'.format(time.strftime('%XL', time.localtime()))
    # outfile handling
    if outfile is not None:
        try:
            with open(outfile, 'wb') as f:
                f.write('')  # clears file prior to loop iteration
        except Exception as e:
            print 'Error clearing {0}: {1}, exiting...'.format(outfile, e)
            exit(2)
        try:
            f = open(outfile, 'ab')
            print '[*] Writing contents to {0}'.format(outfile)
        except Exception as e:
            print 'Error opening {0} to write to: {1}, exiting...'.format(outfile, e)
            exit(2)
    #########################################################################
    # iterate through customer instances to retrieve, parse, and display data
    #########################################################################
    for i in customer_list:
        customer_name = r5.json()['user_customers'][i]['name']  # customer name
        if r5.json()['user_customers'][i]['alias'] == 'ALIAS':  # define any instance alias here to ignore
            continue
        #tmp = {'cid': i}
        try:
            s8 = falcon.post('https://falcon.crowdstrike.com/api2/auth/switch-customer', headers=header, json={'cid': i})
            s9 = falcon.post('https://falcon.crowdstrike.com/api2/auth/verify', headers=header)
            header['X-CSRF-Token'] = s9.json()['csrf_token']
        except requests.exceptions.ConnectionError:
            continue
        #####################################################################
        # insert per instance code below
        #####################################################################
        # alerts
        if alerts:
            tmp_alerts = get_alerts(customer_name)
            if tmp_alerts is not None:
                if outfile is not None:
                    f.write(tmp_alerts)
                else:
                    print tmp_alerts
        # systems
        if systems == 1:
            if outfile is not None:
                f.write(get_machines(customer_name))
            else:
                print get_machines(customer_name)
        elif systems > 1:
            print get_machines(customer_name, full=True)
        #####################################################################
        #####################################################################
    if outfile is not None:
        f.close()
    print '[*] Search complete ({0})'.format(time.strftime('%XL', time.localtime()))


def get_alerts(customer_name):
    """ gets alerts """
    # There are 3 other v1 posts passed per customer with varying payloads.The dictionary below is required to return
    # the necessary data; modifying it can break the request (needs more testing). I know it is not pep8 (too long)
    data_dict = {"name":"time","min_doc_count":0,"size":5,"type":"date_range","field":"last_behavior","date_ranges":[{"from":"now-1h","to":"now","label":"Last hour"},{"from":"now-24h","to":"now","label":"Last day"},{"from":"now-7d","to":"now","label":"Last week"},{"from":"now-30d","to":"now","label":"Last 30 days"},{"from":"now-90d","to":"now","label":"Last 90 days"}]},{"name":"status","min_doc_count":0,"size":5,"type":"terms","field":"status"},{"name":"severity","min_doc_count":0,"size":5,"type":"range","field":"max_severity","ranges":[{"from":80,"to":101,"label":"Critical","id":4},{"from":60,"to":80,"label":"High","id":3},{"from":40,"to":60,"label":"Medium","id":2},{"from":20,"to":40,"label":"Low","id":1},{"from":0,"to":20,"label":"Informational","id":0}]},{"name":"scenario","min_doc_count":0,"size":0,"type":"terms","field":"behaviors.scenario"},{"name":"assigned_to_uid","min_doc_count":1,"size":5,"type":"terms","field":"assigned_to_uid","missing":"Unassigned"},{"name":"host","min_doc_count":1,"size":5,"type":"terms","field":"device.hostname.raw","missing":"Unknown"},{"name":"triggering_file","min_doc_count":1,"size":5,"type":"terms","field":"behaviors.filename.raw"}
    s10 = falcon.post('https://falcon.crowdstrike.com/api2/detects/aggregates/detects/GET/v1', headers=header,
                      data=json.dumps(data_dict))
    if len(s10.json()['resources']) > 0:
        #pp.pprint(s10.json())  # full json data set!
        cust_data = s10.json()
        for bucket in cust_data['resources']:
            if bucket['name'] == 'status':
                for value in bucket['buckets']:
                    if value['label'] == 'new':
                        if 'count' in value and value['count'] > 0:
                            alert_str = customer_name + '\n'
                            alert_str += '*' * len(customer_name) + '\n'
                            alert_str += '[!] {0} alert(s) detected!\n\n'.format(value['count'])
                #pp.pprint(bucket['buckets'])  # for testing!
                            return alert_str


def get_machines(customer_name, full=False):
    """ gets machine info (props to mccrorysensei for the urls) """
    machines = falcon.get('https://falcon.crowdstrike.com/api2/devices/queries/devices/v1?sort=last_seen.desc', headers=header)
    aids = machines.json()['resources']
    url = 'https://falcon.crowdstrike.com/api2/devices/entities/devices/v1?'
    for i in aids:
        url += 'ids={0}&'.format(i)
    url = url.rstrip('&')
    machine_info = falcon.get(url, headers=header)
    machines_str = '\n{0}\n{1}\n'.format(customer_name, '*' * len(customer_name))
    if full:
        machines_str += pp.pformat(machine_info.json()['resources']) + '\n'
        return machines_str
    else:
        machines_str += '{0:<37} {1:<25} {2:<15} {3:<22}\n{4:<37} {5:<25} {6:<15} {7:<22}\n'.format(
            'Hosts', 'Operating System', 'Public IP', 'Last Seen', '-' * 5, '-' * 16, '-' * 9, '-' * 9)
        for machine in machine_info.json()['resources']:
            try:
                machines_str += '{0:<37} {1:<25} {2:<15} {3:<22}\n'.format(
                    machine['hostname'][:35], machine['os_version'][:25], machine['external_ip'][:15], machine['last_seen'][:22])
            except KeyError as e:
                machines_str += 'Issue pulling host info: {0}\n'.format(e)
                continue
    return machines_str


art = '''
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

'''

title = '''
              **********************************************************
                  ______   ______     ______     __  __     __  __
                 /\__  _\ /\  __ \   /\  == \   /\ \/\ \   /\ \/ /
                 \/_/\ \/ \ \ \/\ \  \ \  __<   \ \ \_\ \  \ \  _"-.
                    \ \_\  \ \_____\  \ \_\ \_\  \ \_____\  \ \_\ \_\\
                     \/_/   \/_____/   \/_/ /_/   \/_____/   \/_/\/_/


                      ***** F a l c o n   T o o l   S u i t e *****
                                        zeroex00
              **********************************************************
'''


if __name__ == '__main__':
    print art
    print title
    # loop
    if args.loop is not None:
        print '[*] Loop mode selected'
        print '[*] Running in a loop for {0} hour(s)'.format(args.loop)
        if args.outfile is not None:
            print ('[!] It is not advisable to output to a file while in loop mode, as the contents will be overwitten '
                   'with each loop')
        timeout = time.time() + (60 * 60 * args.loop)
        set_auth()
        while time.time() < timeout:
            toruk(args.alerts, args.systems, args.instance, args.outfile)
            print '[-] Sleeping for 1 minute'
            time.sleep(60)
    else:
        # no loop
        set_auth()
        toruk(args.alerts, args.systems, args.instance, args.outfile)
