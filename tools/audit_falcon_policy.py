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
import csv

from colorama import init, Fore, Back, Style
import requests

# colorama init
init(autoreset=True)
config = ConfigParser.RawConfigParser()
falcon = requests.Session()
parser = argparse.ArgumentParser(description='Audit policies of all customers')
header = {
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US; q=0.7, en; q=0.3',
        'Cache-Control': 'no-cache',
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'user-agent': 'Mozilla'
        }
FALCON_UNAME = ''
FALCON_PASS = ''
FALCON_OTP = ''


parser.add_argument('-i', '--instance', type=str, help='cid for specific customer instance')
parser.add_argument('-c', '--config-file', type=str, help='select a config file with user credentials')
parser.add_argument('-csv', help='output to specified csv file')
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
            if config.has_option('Falconhost', 'username'):
                FALCON_UNAME = str(config.get('Falconhost', 'username'))
            if config.has_option('Falconhost', 'password'):
                FALCON_PASS = str(config.get('Falconhost', 'password'))
            if config.has_option('Falconhost', 'otp'):
                FALCON_OTP = str(config.get('Falconhost', 'otp'))
            print info_format('info', 'Credentials read from config file')
        except Exception as e:
            print info_format('alert', 'Check your config file and rerun the program, exiting...\n')
            exit(2)
    if FALCON_UNAME == '':
        FALCON_UNAME = raw_input(info_format('prompt', 'Enter FH Username (email address): '))
    if FALCON_PASS == '':
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


def toruk(customer_cid, ignore=None, to_csv=None):
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
    # verify ignored cid's from config file are actually within customer list
    ignore_info = ''
    if ignore is not None:
        ignore_count = 0
        for entry in ignore:
            if entry in customer_list:
                ignore_count += 1
        ignore_info = '({0} ignored)'.format(ignore_count)
    print info_format('info', '{0}{1}{2} customer instances detected {3}'.format(Fore.LIGHTGREEN_EX, len(customer_list),
                                                                             Fore.LIGHTWHITE_EX, ignore_info))
    print info_format('info', 'Performing search ({0})...'.format(time.strftime('%XL', time.localtime())))
    print info_format('info', '********************************')
    #########################################################################
    # iterate through customer instances to retrieve, parse, and display data
    #########################################################################
    if ignore is not None:
        count_cust = len(customer_list) - ignore_count
    else:
        count_cust = len(customer_list)
    count = 1
    if to_csv:
        csv_file = open(to_csv, 'wb')
        csv_writer = csv.writer(csv_file)
        titles = [
            'Customer',
            'Category',
            'Sub-Category',
            'Setting',
            'Value',
            'Sub-Value'
            ]
        csv_writer.writerow(titles)
    else:
        csv_file = None
        csv_writer = None
    for i in customer_list:
        customer_name = r5.json()['user_customers'][i]['name']  # customer name
        if ignore is not None:
            if i in ignore:
                continue
        if r5.json()['user_customers'][i]['alias'] == 'ALIAS':  # define any instance alias here to ignore
            continue
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
        # policy
        get_policy(customer_name, csv_writer)
        #####################################################################
        #####################################################################
    print info_format('info', 'Search complete ({0})'.format(time.strftime('%XL', time.localtime())))
    if to_csv:
        csv_file.close()


def print_policy(customer_name, raw_policy):
    print 'POLICY FOR {1}{0}{2}\n'.format(customer_name, Fore.LIGHTRED_EX, Style.RESET_ALL)
    # print 'DEBUG {}'.format(policies)
    for setting in raw_policy.get('prevention_settings'):
        print 'Category: {1}{0}{2}'.format(setting.get('name'), Fore.LIGHTMAGENTA_EX, Style.RESET_ALL)
        for category_setting in setting.get('categories'):
            print '\tSub-category: {1}{0}{2}'.format(category_setting.get('name'), Fore.LIGHTMAGENTA_EX,
                                                     Style.RESET_ALL)
            for each_cat_setting in category_setting.get('settings'):
                if each_cat_setting.get('value').get('enabled') is True:
                    print '{1}\t\tENABLED SETTING: {0}{2}'.format(each_cat_setting.get('name'),
                                                                  Fore.LIGHTGREEN_EX, Style.RESET_ALL)
                elif len(each_cat_setting.get('value')) > 1:
                    print '{1}\t\tENABLED SETTING: {0}{2}'.format(each_cat_setting.get('name'),
                                                                  Fore.LIGHTGREEN_EX, Style.RESET_ALL)
                    print '{1}\t\t\tVALUES: {0}{2}'.format(each_cat_setting.get('value'),
                                                           Fore.LIGHTYELLOW_EX, Style.RESET_ALL)
    print


def csv_policy(customer_name, raw_policy, csv_writer):
    # customer category sub-category setting value sub-value
    print 'Pulled policy for {1}{0}{2}'.format(customer_name, Fore.LIGHTRED_EX, Style.RESET_ALL)
    # print 'DEBUG {}'.format(policies)
    for setting in raw_policy.get('prevention_settings'):
        category = setting.get('name')
        for category_setting in setting.get('categories'):
            sub_category = category_setting.get('name')
            for each_cat_setting in category_setting.get('settings'):
                setting = each_cat_setting.get('name')
                if len(each_cat_setting.get('value')) > 1:
                    for each_value, value in each_cat_setting.get('value').items():
                        #value = each_value.get
                        csv_writer.writerow([customer_name, category, sub_category, setting, each_value, value])
                else:
                    value = each_cat_setting.get('value').get('enabled')
                    csv_writer.writerow([customer_name, category, sub_category, setting, value])


def get_policy(customer_name, csv_writer):
    """ more detailed version of alert information """
    s_id = falcon.get('https://falcon.crowdstrike.com/api2/policies/queries/prevention/v1?limit=500&offset=0', headers=header)
    try:
        ids = s_id.json()['resources']
        #print 'DEBUG: {}'.format(ids)
    except Exception as e:
        print info_format('alert', 'Failed to pull policy for {0}: 1-{1}'.format(customer_name, e))
        return

    s_p = falcon.get('https://falcon.crowdstrike.com/api2/policies/entities/prevention/v2?ids={0}'.format('&ids='.join(ids)), headers=header)

    try:
        policies = s_p.json()['resources']  # list
        #print 'DEBUG {}'.format(policies)
        for policy in policies:
            if policy.get('name').lower() == 'platform_default' and policy.get('platform_name').lower() == 'windows':
                if csv_writer:
                    csv_policy(customer_name, policy, csv_writer)
                else:
                    print_policy(customer_name, policy)
            else:
                continue
    except Exception as e:  #KeyError:
        print info_format('alert', 'Failed to pull policy for {0}: 2-{1}'.format(customer_name, e))
        return


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
    # parse ignore list from configs
    ignore_list = None
    if args.config_file is not None:
        try:
            config.read(args.config_file)
            if config.has_option('Falconhost', 'ignore'):
                ignore_list_dirty = list(config.get('Falconhost', 'ignore').split(','))
                ignore_list = map(lambda x: x.strip(), ignore_list_dirty)
                if ignore_list[0] == '':
                    ignore_list = None
        except Exception as e:
            print info_format('alert', 'Could not parse ignore section of config file: {0}').format(e)

    set_auth()
    toruk(args.instance, ignore_list, args.csv)

if __name__ == '__main__':
    main()
