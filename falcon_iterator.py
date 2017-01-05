#!/usr/bin/python
#
# FalconIteratorSuite
#
# Currently iterates through current customer instances within falconhost

from selenium import webdriver
from selenium.webdriver.common.keys import Keys
import time
import getpass
#import ConfigParser

# get inputs from the user
browser = webdriver.Firefox()
fhURL = "https://falcon.crowdstrike.com/login/"  # verify that url has not changed
browser.get(fhURL)
custList = []  # customer list as populated by falconHost

'''
try:
    # get the configuration from file
    config = ConfigParser.ConfigParser()
    config.readfp(open('albert.cfg'))
    albertChatUser = config.get('chat', 'user')
    albertChatPass = config.get("chat", "pass")
except:
    print "Missing config file, section, or required key"
    exit() '''

# falconhost logon
def falconHostLogon():
    # web elements for authenticating
    myname          = raw_input('Enter FalconHost UserName: ')
    mypass          = getpass.getpass(prompt='Enter FalconHost Password: ')          # FH pass
    mykey           = raw_input("Enter FalconHost 2FA Token: ")                      # FH 2FA
    # start authentication process; enters uname & pw
    print "Authenticating to FalconHost"
    time.sleep(1)
    username        = browser.find_element_by_id("username")
    password        = browser.find_element_by_id("password")
    login_attempt   = browser.find_element_by_xpath("//*[@type='submit']")
    username.send_keys(myname)
    password.send_keys(mypass)
    login_attempt.submit()
    # delay, then 2fa token submission
    time.sleep(3)
    token           = browser.find_element_by_id("token")
    keysubmit       = browser.find_element_by_xpath("//*[@type='submit']")
    token.send_keys(mykey)
    print "Token entered."
    keysubmit.submit()
    # add error handling
    print "Login successful"

# gets list of current customer FH instances
def getCustList():
    global custList  # customer list as populated by falconHost
    del custList[:]
    cid = browser.find_element_by_xpath("//*[@class='hide-wrapper']")
    temp = cid.text.split('\n')
    for i in temp:
        if i.find("Current") == -1:
            try:
                custList.append(str(i))
            except UnicodeEncodeError:
                print "DEBUG: Encoding error, character %s not ascii...skipping" % i
                continue
    print "DEBUG: current list of customers:"
    for i in custList:
        print i

# rotates through customer instances
def rotateFalconHost():
    print "# of customers %d" % len(custList)
    for i in custList:
        select = browser.find_element_by_xpath('/html/body/nav/ol[2]/li[1]/div/select')
        select.send_keys(i)
        select.send_keys(Keys.RETURN)
        print "Currently in %s environment" % i
        time.sleep(7)

falconHostLogon()
time.sleep(2)
while True:
    getCustList()
    for i in xrange(5):
        rotateFalconHost()
