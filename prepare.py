# preparation module for toruk

from os import system
from sys import platform


# reqests or colorama
missing = []
try:
    import requests
except ImportError:
    missing.append('requests')
try:
    from colorama import init, Fore, Back, Style
except ImportError:
    missing.append('colorama')
if len(missing) > 0:
    command = 'pip install '
    # linux requires root for pip
    if platform == 'linux2':
        from os import getuid
        if getuid() != 0:
            print '[!] You are missing some dependencies which require root to install! {0}'.format(missing)
            command = 'sudo pip install '
        else:
            print '[!] You are missing some dependencies! {0}'.format(missing)
    else:
        print '[!] You are missing some dependencies! {0}'.format(missing)
    answer = ''
    for i in xrange(3):
        answer = raw_input('[$] Do you want to continue with installation [y/N]? ')
        if answer == 'y':
            # install
            if 'requests' in missing:
                system(command + 'requests')
                import requests
            if 'colorama' in missing:
                system(command + 'colorama')
                from colorama import init, Fore, Back, Style
            break
        elif answer == 'N':
            break
    # no answer after 3 inquiries
    if answer != 'y':
        print '[!] Please manually install the dependencies (pip install <module>) and re-run. Exiting...'
        exit(1)
