# MIT License
# br0k3ns0und

import argparse
import ConfigParser
from getpass import getpass
import json
import time

from colorama import init, Fore, Back, Style
import requests


# colorama init
init(autoreset=True)
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
                    help='runs toruk in a loop, for the number of hours passed')
parser.add_argument('-f', '--frequency', type=int, default=1, help='frequency (in minutes) for the loop to resume')
parser.add_argument('-q', '--quiet', action='store_true', help='suppresses errors from alert retrieval failures')
args = parser.parse_args()


def info_format(print_type, text):
    # info, prompt, alert, sleep
    lb = '{0}[{1}'.format(Fore.LIGHTGREEN_EX, Style.RESET_ALL)
    rb = '{0}]{1}'.format(Fore.LIGHTGREEN_EX, Style.RESET_ALL)
    new_text = Fore.LIGHTWHITE_EX + text + Style.RESET_ALL
    if print_type == 'info':
        return '{0}{1}*{2}{3} {4}'.format(lb, Fore.LIGHTGREEN_EX, Style.RESET_ALL, rb, new_text)
    elif print_type == 'prompt':
        return '{0}{1}${2}{3} {4}'.format(lb, Fore.LIGHTYELLOW_EX, Style.RESET_ALL, rb, new_text)
    elif print_type == 'alert':
        return '{0}{1}!{2}{3} {4}'.format(lb, Fore.LIGHTRED_EX, Style.RESET_ALL, rb, new_text)
    elif print_type == 'sleep':
        return '{0}-{1} {2}'.format(lb, rb, new_text)


def set_auth():
    global FALCON_UNAME
    global FALCON_PASS
    if args.config_file is not None:
        try:
            config.read(args.config_file)
            FALCON_UNAME = str(config.get('Falconhost', 'username'))
            FALCON_PASS = str(config.get('Falconhost', 'password'))
            print info_format('info', 'Credentials read from config file')
        except Exception as e:
            print info_format('alert', 'Check your config file and rerun the program, exiting...\n')
            exit(2)
    else:
        FALCON_UNAME = raw_input(info_format('prompt', 'Enter FH Username (email address): '))
        FALCON_PASS = getpass(prompt='[$] Enter FH Password: ')


def falcon_auth():
    """ Authentication Process """
    falcon.get('https://falcon.crowdstrike.com/login/', headers=header)
    r2 = falcon.post('https://falcon.crowdstrike.com/api2/auth/csrf', headers=header)
    header['X-CSRF-Token'] = r2.json()['csrf_token']
    fh_2fa = raw_input(info_format('prompt', 'Enter FH 2FA: '))
    auth_data = {'username': FALCON_UNAME, 'password': FALCON_PASS, '2fa': fh_2fa}
    falcon.post('https://falcon.crowdstrike.com/auth/login', headers=header, data=json.dumps(auth_data))
    falcon.get('https://falcon.crowdstrike.com')


def toruk(alerts, systems, customer_cid, outfile, quiet):
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
        print info_format('alert', 'Check your credentials and rerun the program, exiting...\n')
        exit(2)
    # customer_cid handling (if passed)
    if customer_cid is not None:
        customer_list = [customer_cid]
    ###################################
    print info_format('info', '{0}{1}{2} customer instances detected'.format(Fore.LIGHTGREEN_EX, len(customer_list),
                                                                             Fore.LIGHTWHITE_EX))
    print info_format('info', 'Performing search ({0})...'.format(time.strftime('%XL', time.localtime())))
    print info_format('info', '********************************')
    # outfile handling
    if outfile is not None:
        try:
            with open(outfile, 'wb') as f:
                f.write('')  # clears file prior to loop iteration
        except Exception as e:
            print info_format('alert', 'Error clearing {0}: {1}, exiting...'.format(outfile, e))
            exit(2)
        try:
            f = open(outfile, 'ab')
            print info_format('info', 'Writing contents to {0}'.format(outfile))
            f.write('Report generated by: {0}\n'
                    'Report generation start time: {1}\n'
                    'Total instances: {2}\n'
                    'Report powered by: Toruk\n'
                    '{3}\n'.format(FALCON_UNAME, time.strftime('%XL', time.localtime()), len(customer_list), '=' * 75))
        except Exception as e:
            print info_format('alert', 'Error opening {0} to write to: {1}, exiting...'.format(outfile, e))
            exit(2)
    #########################################################################
    # iterate through customer instances to retrieve, parse, and display data
    #########################################################################
    for i in customer_list:
        customer_name = r5.json()['user_customers'][i]['name']  # customer name
        if r5.json()['user_customers'][i]['alias'] == 'ALIAS':  # define any instance alias here to ignore
            continue
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
            tmp_alerts = get_alerts(customer_name, quiet)
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
            if outfile is not None:
                f.write(get_machines(customer_name, full=True))
            else:
                print get_machines(customer_name, full=True)
        #####################################################################
        #####################################################################
    if outfile is not None:
        f.write('\n{0}\nReport completion time: {1}'.format('=' * 75, time.strftime('%XL', time.localtime())))
        f.close()
    print info_format('info', 'Search complete ({0})'.format(time.strftime('%XL', time.localtime())))


def get_alerts(customer_name, quiet=False):
    """ gets alerts """
    # There are 3 other v1 posts passed per customer with varying payloads.The dictionary below is required to return
    # the necessary data; modifying it can break the request (needs more testing). I know it is not pep8 (too long)
    data_dict = {"name":"time","min_doc_count":0,"size":5,"type":"date_range","field":"last_behavior","date_ranges":[{"from":"now-1h","to":"now","label":"Last hour"},{"from":"now-24h","to":"now","label":"Last day"},{"from":"now-7d","to":"now","label":"Last week"},{"from":"now-30d","to":"now","label":"Last 30 days"},{"from":"now-90d","to":"now","label":"Last 90 days"}]},{"name":"status","min_doc_count":0,"size":5,"type":"terms","field":"status"},{"name":"severity","min_doc_count":0,"size":5,"type":"range","field":"max_severity","ranges":[{"from":80,"to":101,"label":"Critical","id":4},{"from":60,"to":80,"label":"High","id":3},{"from":40,"to":60,"label":"Medium","id":2},{"from":20,"to":40,"label":"Low","id":1},{"from":0,"to":20,"label":"Informational","id":0}]},{"name":"scenario","min_doc_count":0,"size":0,"type":"terms","field":"behaviors.scenario"},{"name":"assigned_to_uid","min_doc_count":1,"size":5,"type":"terms","field":"assigned_to_uid","missing":"Unassigned"},{"name":"host","min_doc_count":1,"size":5,"type":"terms","field":"device.hostname.raw","missing":"Unknown"},{"name":"triggering_file","min_doc_count":1,"size":5,"type":"terms","field":"behaviors.filename.raw"}
    s10 = falcon.post('https://falcon.crowdstrike.com/api2/detects/aggregates/detects/GET/v1', headers=header,
                      data=json.dumps(data_dict))
    try:
        if len(s10.json()['resources']) > 0:
            # print(json.dumps(s10.json(), indent=4))  # full json data set!
            cust_data = s10.json()
            for bucket in cust_data['resources']:
                if bucket['name'] == 'status':
                    for value in bucket['buckets']:
                        if value['label'] == 'new':
                            if 'count' in value and value['count'] > 0:
                                alert_str = info_format('alert', '{0}{1}{2} alert(s) detected!\n'.format(
                                    Fore.LIGHTRED_EX, value['count'], Fore.LIGHTWHITE_EX))
                                alert_str += '----> {0}{1}{2}'.format(Fore.LIGHTGREEN_EX, customer_name, Style.RESET_ALL)
                    # print(json.dumps(bucket['buckets'], indent=4))  # for testing!
                                return alert_str
    except KeyError:
        if not quiet:
            return info_format('alert', 'There was an issue retrieving alerts for {0}. Skipping...'.format(customer_name))
        else:
            return None


def get_machines(customer_name, full=False):
    """ gets machine info (props to mccrorysensei for the urls) """
    machines = falcon.get('https://falcon.crowdstrike.com/api2/devices/queries/devices/v1?sort=last_seen.desc',
                          headers=header)
    try:
        aids = machines.json()['resources']
        url = 'https://falcon.crowdstrike.com/api2/devices/entities/devices/v1?'
        for i in aids:
            url += 'ids={0}&'.format(i)
        url = url.rstrip('&')
        machine_info = falcon.get(url, headers=header)
        machines_str = '\n{0}\n{1}\n'.format(customer_name, '=' * len(customer_name))
        if full:
            machines_str += json.dumps(machine_info.json()['resources'], indent=4) + '\n'
            return machines_str
        else:
            machines_str += '{0:<37} {1:<25} {2:<15} {3:<22}\n{4:<37} {5:<25} {6:<15} {7:<22}\n'.format(
                'Hosts', 'Operating System', 'Public IP', 'Last Seen', '-' * 5, '-' * 16, '-' * 9, '-' * 9)
            for machine in machine_info.json()['resources']:
                try:
                    machines_str += '{0:<37} {1:<25} {2:<15} {3:<22}\n'.format(machine['hostname'][:35],
                                    machine['os_version'][:25], machine['external_ip'][:15], machine['last_seen'][:22])
                except Exception as e:
                    machines_str += 'Issue pulling host info: {0}\n'.format(e)
                    continue
            return machines_str
    except KeyError:
        return info_format('alert', 'There was an issue retrieving system info for {0}. Skipping...\n'.format(customer_name))


def main():
    # must choose something to do
    if args.systems < 1 and not args.alerts:
        print info_format('alert', 'You must have something for toruk to do (-a or -s), exiting...')
        exit(0)
    # loop
    if args.loop is not None:
        print info_format('info', 'Loop mode selected')
        print info_format('info', 'Running in a loop for {0} hour(s)'.format(args.loop))
        if args.outfile is not None:
            print info_format('alert', 'It is not advisable to output to a file while in loop mode, as the contents '
                                       'will be overwritten with each loop')
        timeout = time.time() + (60 * 60 * args.loop)
        set_auth()
        while time.time() < timeout:
            toruk(args.alerts, args.systems, args.instance, args.outfile, args.quiet)
            print info_format('sleep', 'Sleeping for {} minute(s)'.format(args.frequency))
            # sleeps for the the number of minutes passed by parameter (default 1 minute)
            time.sleep(args.frequency * 60)
    else:
        # no loop
        set_auth()
        toruk(args.alerts, args.systems, args.instance, args.outfile, args.quiet)


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

title = '''{0}
              **********************************************************
                  ______   ______     ______     __  __     __  __
                 /\__  _\ /\  __ \   /\  == \   /\ \/\ \   /\ \/ /
                 \/_/\ \/ \ \ \/\ \  \ \  __<   \ \ \_\ \  \ \  _"-.
                    \ \_\  \ \_____\  \ \_\ \_\  \ \_____\  \ \_\ \_\\
                     \/_/   \/_____/   \/_/ /_/   \/_____/   \/_/\/_/


                      {1}***** F a l c o n   T o o l   S u i t e *****{2}
                                        zeroex00
              **********************************************************{3}
'''.format(Fore.LIGHTWHITE_EX, Fore.LIGHTRED_EX, Fore.LIGHTWHITE_EX, Style.RESET_ALL)


if __name__ == '__main__':
    print Fore.LIGHTRED_EX + art + Style.RESET_ALL
    print title
    try:
        main()
    except requests.ConnectionError:
        print info_format('alert', 'You encountered a connection error, re-run')
        exit(2)
