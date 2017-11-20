# MIT License
# br0k3ns0und

import argparse
import ConfigParser
from getpass import getpass
import json
import time
import os
import sys
import pyotp

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
FALCON_OTP = ''


class MasterAlerts(object):
    def __init__(self):
        self.alerts_old_list = []


master_alerts = MasterAlerts()

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
parser.add_argument('-d', '--detailed', action='store_true', help='returns detailed alert information')
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


def enum_alert(raw_data):
    flat_dict = {}
    for k, v in raw_data.items():
        # hostinfo
        if k == 'hostinfo':
            for k2, v2 in v.items():
                flat_dict[k2] = v2
                # print '{}: {}'.format(k2, v2)  # debug
        # device
        elif k == 'device':
            for k2, v2 in v.items():
                flat_dict[k2] = v2
                # print '{}: {}'.format(k2, v2)  # debug
        # behaviors
        elif k == 'behaviors':
            for item2 in v:
                for k2, v2 in item2.items():
                    if k2 == 'parent_details':
                        for k3, v3 in v2.items():
                            flat_dict[k3] = v3
                            # print '{}: {}'.format(k3, v3)  # debug
                    else:
                        flat_dict[k2] = v2
                        # print '{}: {}'.format(k2, v2)  # debug
        else:
            flat_dict[k] = v
            # print '{}: {}'.format(k, v)  # debug
    return flat_dict


def parse_alert(customer_name, raw_data):
    flat_dict = enum_alert(raw_data)
    # generate alert link
    #part1 = flat_dict['detection_id'].split(':')  # 1,2
    #part2 = flat_dict['triggering_process_graph_id'].split(':') # 2
    #alert_link = 'https://falcon.crowdstrike.com/activity/detections/detail/{0}/{1}?pid={2}'.format(
    #    part1[1], part1[2], part2[2])

    # description
    description = ('{23}{20}{24} - {21}{0}{24} alert on {22}{1}{24} for {23}{2}{24} ({3})!\n'
                    '\t{21}        cid{24}: {4} {21}aid{24}: {5}\n'
                    '    {22}SYSTEM INFO{24}:\n'
                    '\t{21}   username{24}: {6}\n'
                    '\t{21}         os{24}: {7}\n'
                    '\t{21}description{24}: {8}\n'
                    '\t{21}     domain{24}: {9}\n'
                    '\t{21}         ou{24}: {10}\n'
                    '\t{21} victim IPs{24}: \n\t\tprivate: {11}\n\t\t public: {12}\n'
                    '    {22}ALERT INFO{24}:\n'
                    '\t{21}   filename{24}: {13}\n'
                    '\t{21}     hashes{24}: \n\t\tsha256: {14}\n\t\t   md5: {15}\n'
                    '\t{21}    cmdline{24}: {16}\n'
                    '    {22}ALERT PARENT INFO{24}:\n'
                    '\t{21}    cmdline{24}: {17}\n'
                    '\t{21}     hashes{24}: \n\t\tsha256: {18}\n\t\t   md5: {19}'.format(
                        flat_dict.get('max_severity_displayname'),
                        flat_dict.get('hostname'),
                        flat_dict.get('scenario'),
                        flat_dict.get('timestamp'),
                        flat_dict.get('cid'),
                        flat_dict.get('device_id'),
                        '{0} ({1})'.format(flat_dict.get('user_name'), flat_dict.get('user_id')),
                        flat_dict.get('os_version'),
                        flat_dict.get('product_type_desc'),
                        flat_dict.get('machine_domain'),
                        flat_dict.get('ou'),
                        flat_dict.get('local_ip'),
                        flat_dict.get('external_ip'),
                        flat_dict.get('filename'),
                        flat_dict.get('sha256'),
                        flat_dict.get('md5'),
                        flat_dict.get('cmdline'),
                        flat_dict.get('parent_cmdline'),
                        flat_dict.get('parent_sha256'),
                        flat_dict.get('parent_md5'),
                        customer_name,
                        # 21                22                  23                  24
                        Fore.LIGHTYELLOW_EX, Fore.LIGHTGREEN_EX, Fore.LIGHTRED_EX, Style.RESET_ALL
                        ))
    return description


def clear_screen():
    if sys.platform == 'win32':
        os.system('cls')
    else:
        os.system('clear')


def set_auth():
    global FALCON_UNAME
    global FALCON_PASS
    global FALCON_OTP
    if args.config_file is not None:
        try:
            config.read(args.config_file)
            FALCON_UNAME = str(config.get('Falconhost', 'username'))
            FALCON_PASS = str(config.get('Falconhost', 'password'))
            FALCON_OTP = str(config.get('Falconhost', 'otp'))
            print info_format('info', 'Credentials read from config file')
        except Exception as e:
            print info_format('alert', 'Check your config file and rerun the program, exiting...\n')
            exit(2)
    else:
        FALCON_UNAME = raw_input(info_format('prompt', 'Enter FH Username (email address): '))
        FALCON_PASS = getpass(prompt='[$] Enter FH Password: ')


def falcon_auth():
    """ Authentication Process """
    global FALCON_OTP
    falcon.get('https://falcon.crowdstrike.com/login/', headers=header)
    r2 = falcon.post('https://falcon.crowdstrike.com/api2/auth/csrf', headers=header)
    header['X-CSRF-Token'] = r2.json()['csrf_token']
    if FALCON_OTP == '':
        fh_2fa = raw_input(info_format('prompt', 'Enter FH 2FA: '))
    else:
        totp = pyotp.TOTP(FALCON_OTP)
        fh_2fa = totp.now()
    auth_data = {'username': FALCON_UNAME, 'password': FALCON_PASS, '2fa': fh_2fa}
    falcon.post('https://falcon.crowdstrike.com/auth/login', headers=header, data=json.dumps(auth_data))
    falcon.get('https://falcon.crowdstrike.com')


def toruk(alerts, systems, customer_cid, outfile, quiet, full):
    falcon.get('https://falcon.crowdstrike.com')
    r5 = falcon.post('https://falcon.crowdstrike.com/api2/auth/verify', headers=header)
    if r5.status_code != 200:
        falcon_auth()
        r5 = falcon.post('https://falcon.crowdstrike.com/api2/auth/verify', headers=header)
    clear_screen()
    print title
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
    for residual_alerts in master_alerts.alerts_old_list:
        if full:
            print info_format('alert', residual_alerts)
        else:
            print residual_alerts
    alerts_new_list = []
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
    count_cust = len(customer_list)
    count = 1
    for i in customer_list:
        customer_name = r5.json()['user_customers'][i]['name']  # customer name
        if r5.json()['user_customers'][i]['alias'] == 'ALIAS':  # define any instance alias here to ignore
            continue
        try:
            sys.stdout.write('\r [{0}/{1}] {2}{3}'.format(count, count_cust, customer_name, ' ' * 25))
            sys.stdout.flush()
        except Exception as e:
            #print 'DEBUG: {}'.format(e)
            continue
        print '\r',
        count += 1
        try:
            s8 = falcon.post('https://falcon.crowdstrike.com/api2/auth/switch-customer', headers=header, json={'cid': i})
            s9 = falcon.post('https://falcon.crowdstrike.com/api2/auth/verify', headers=header)
            header['X-CSRF-Token'] = s9.json()['csrf_token']
        except requests.exceptions.ConnectionError:
            continue
        except KeyError:
            print info_format('info', 'Session timed out. Resetting...')
            falcon_auth()
            continue
        #####################################################################
        # insert per instance code below
        #####################################################################
        # alerts
        if alerts:
            #tmp_alerts = get_alerts(customer_name, quiet)  # reserved as a backup method
            tmp_alerts = get_alerts_detailed(customer_name, quiet, full)
            if tmp_alerts is not None:
                if outfile is not None:
                    f.write(tmp_alerts)
                else:
                    if full:
                        for each_alert in tmp_alerts:
                            format_alert = parse_alert(customer_name, each_alert)
                            if format_alert not in master_alerts.alerts_old_list:
                                print info_format('alert', format_alert)
                            alerts_new_list.append(parse_alert(customer_name, each_alert))
                    else:
                        if tmp_alerts not in master_alerts.alerts_old_list:
                            print tmp_alerts
                        alerts_new_list.append(tmp_alerts)
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
    master_alerts.alerts_old_list = list(alerts_new_list)
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


def get_alerts_detailed(customer_name, quiet=False, full=False):
    """ more detailed version of alert information """
    s11 = falcon.get('https://falcon.crowdstrike.com/api2/detects/queries/detects/v1?filter=&limit=20&offset=0&q=&sort=last_behavior|desc',
                     headers=header)
    try:
        resource_list = s11.json()['resources']
        s12 = falcon.post('https://falcon.crowdstrike.com/api2/detects/entities/summaries/GET/v1',
                          headers=header, data=json.dumps({'ids': resource_list}))
        #print json.dumps(s12.json()['resources'], indent=4)
        alert_str = ''
        alert_list_full = []
        alert_count = 0
        for alert in s12.json()['resources']:
            if alert['status'] == 'new':
                alert_count += 1
                if full:
                    alert_list_full.append(alert)
                    continue
                alert_host = alert['device']['hostname']
                alert_severity = alert['max_severity_displayname']
                alert_reason = alert['behaviors'][0]['scenario']
                alert_time = alert['behaviors'][0]['timestamp']
                alert_str += info_format('alert', '{0}{1}{6} alert on {2}{3}{6} for {4}{5}{6} ({7})!\n'.format(
                    Fore.LIGHTYELLOW_EX, alert_severity, Fore.LIGHTGREEN_EX, alert_host, Fore.LIGHTRED_EX, alert_reason,
                    Style.RESET_ALL, alert_time))
        if alert_count > 0:
            alert_str += '----> {0}{1}{2}'.format(Fore.LIGHTGREEN_EX, customer_name, Style.RESET_ALL)
            if full:
                return alert_list_full
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


def main():
    clear_screen()
    print Fore.LIGHTRED_EX + art + Style.RESET_ALL
    print title
    # must choose something to do
    if args.systems < 1 and not args.alerts:
        print info_format('alert', 'You must have something for toruk to do (-a or -s), exiting...')
        exit(0)
    # loop
    if args.loop is not None:
        print info_format('info', 'Loop mode selected')
        print info_format('info', 'Running in a loop for {0} hour(s)'.format(args.loop))
        if args.outfile is not None:
            print info_format('alert', 'It is not advisable to output to a file while in loop mode, as the contents'
                                       ' will be overwritten with each loop')
        timeout = time.time() + (60 * 60 * args.loop)
        set_auth()
        while time.time() < timeout:
            try:
                toruk(args.alerts, args.systems, args.instance, args.outfile, args.quiet, args.detailed)
            except requests.ConnectionError:
                print info_format('alert', 'You encountered a connection error, re-running...')
                pass
            print info_format('sleep', 'Sleeping for {} minute(s)'.format(args.frequency))
            # sleeps for the the number of minutes passed by parameter (default 1 minute)
            time.sleep(args.frequency * 60)
    # no loop
    else:
        set_auth()
        try:
            toruk(args.alerts, args.systems, args.instance, args.outfile, args.quiet, args.detailed)
        except requests.ConnectionError:
            print info_format('alert', 'You encountered a connection error, re-run')
            exit(2)


if __name__ == '__main__':
    main()
