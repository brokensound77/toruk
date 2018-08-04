# MIT License
# br0k3ns0und
# This gets you access to the Falcon Host Splunk service driving EAM
# For full capability and features, refer to the following links. The system accesses a "Splunk Search Endpoint"
#   - http://dev.splunk.com/restapi
#   - http://docs.splunk.com/Documentation/Splunk/7.0.1/RESTREF/RESTsearch  # this is your primary doc!!

import argparse
import ConfigParser
import json
import pyotp
import requests
import time
#import re


parser = argparse.ArgumentParser()
parser.add_argument('-c', '--config-file', type=str, required=True, help='select a config file with user credentials')
parser.add_argument('-q', '--query', required=True, help='the search query')
args = parser.parse_args()


class FalconAuth(object):

    def __init__(self, config_file):
        self.sesh = requests.Session()
        self.head = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US; q=0.7, en; q=0.3',
            'Cache-Control': 'no-cache',
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'user-agent': 'Mozilla'
            }
        self.username = ''
        self.password = ''
        self.otp_key = ''
        self.customer_cid = ''
        self.parse_configs(config_file)
        self.falcon_auth()

    def parse_configs(self, config_file):
        config = ConfigParser.RawConfigParser()
        if config_file is not None:
            try:
                config.read(args.config_file)
                if config.has_option('Falconhost', 'username'):
                    self.username = config.get('Falconhost', 'username')
                if config.has_option('Falconhost', 'password'):
                    self.password = config.get('Falconhost', 'password')
                if config.has_option('Falconhost', 'otp'):
                    self.otp_key = config.get('Falconhost', 'otp')
                if config.has_option('Falconhost', 'cid'):
                    self.customer_cid = config.get('Falconhost', 'cid')
            except Exception as e:
                exit(2)

    def falcon_auth(self):
        """ Authentication Process """
        self.sesh.get('https://falcon.crowdstrike.com/login/', headers=self.head)
        r2 = self.sesh.post('https://falcon.crowdstrike.com/api2/auth/csrf', headers=self.head)
        self.head['X-CSRF-Token'] = r2.json()['csrf_token']
        totp = pyotp.TOTP(self.otp_key)
        fh_2fa = totp.now()
        auth_data = {'username': self.username, 'password': self.password, '2fa': fh_2fa}
        self.sesh.post('https://falcon.crowdstrike.com/auth/login', headers=self.head, data=json.dumps(auth_data))
        self.sesh.get('https://falcon.crowdstrike.com')
        r5 = self.sesh.post('https://falcon.crowdstrike.com/api2/auth/verify', headers=self.head)
        try:
            self.head['X-CSRF-Token'] = r5.json()['csrf_token']
        except KeyError:
            exit(2)
        try:
            self.sesh.post('https://falcon.crowdstrike.com/api2/auth/switch-customer',
                           headers=self.head, json={'cid': self.customer_cid})
            s9 = self.sesh.post('https://falcon.crowdstrike.com/api2/auth/verify', headers=self.head)
            self.head['X-CSRF-Token'] = s9.json()['csrf_token']
        except KeyError:
            exit()


def job_test(falcon_session, query):
    s00 = falcon_session.sesh.get('https://falcon.crowdstrike.com/eam/en-US/app/eam2/audit_app?earliest=-14d&latest=now'
                    '&form.analyst_tok=*&form.service_tok=Crowdstrike%20Authentication&form.customer_tok=*')
    url = 'https://falcon.crowdstrike.com/eam/en-US/splunkd/__raw/servicesNS/csuser/eam2/search/jobs'
    earliest_time = '-2h'#4h'  # '-3d'  # change to whatever you want or make it a parameter to pass
    latest_time = 'now'

    query_data = {
        'auto_cancel': 90,
        'status_buckets': 0,
        'output_mode': 'json',
        'label': 'search2',
        'preview': 'true',
        'provenance': 'UI:Dashboard:audit_app',
        'earliest_time': earliest_time,
        'latest_time': latest_time,
        'webframework.cache.hash': 'java5:-2988cbf5',
        'search': query
    }

    s_job = falcon_session.sesh.post(url, headers=falcon_session.head, data=query_data)
    print s_job.text
    sid = s_job.json()['sid']
    print 'search ID: {0}'.format(sid)

    #print 'Sleeping for 5 seconds to allow search to run'
    #time.sleep(5)

    # TODO: with the session, header, and sid (into the parameter) the full Splunk search endpoint is accessible from
    # TODO:     here!!!

    # change control to save search (default 7 days)
    #control_data = {'action': 'save'}
    #control = falcon_session.sesh.post('{0}/{1}/control'.format(url, sid), headers=falcon_session.head, data=control_data)
    #print control.text

    status = 'WAIT'

    while status != 'DONE':
        status0 = falcon_session.sesh.get(
            'https://falcon.crowdstrike.com/eam/en-US/splunkd/__raw/servicesNS/csuser/eam2/search/jobs/{0}?output_mode=json'.format(
                sid), headers=falcon_session.head)
        #status =  re.search('name="dispatchState">(?P<dispatch_state>.+?)<', status0.text).group('dispatch_state')
        status = status0.json()['entry'][0]['content']['dispatchState']
        #print json.dumps(status0.json(), indent=4)
        print status
        time.sleep(2)

    results = falcon_session.sesh.get(
        'https://falcon.crowdstrike.com/eam/en-US/splunkd/__raw/servicesNS/csuser/eam2/search/jobs/{0}/results?output_mode=json'.format(
            sid), headers=falcon_session.head)
    #return results.text.encode('ascii', 'replace')
    return results.json()['results']


if __name__ == '__main__':
    f = FalconAuth(args.config_file)
    #print job_test(f, args.query)
    print json.dumps(job_test(f, args.query), indent=4)
    # or just move the job test into the class, and return the object with the session and add the sid as an attribute
    # for better programmatic access to the Splunk service
