import re
from urllib.request import urlopen
from json import loads
from argparse import ArgumentParser
import subprocess


def get_location(ip):
    message = ''
    info = loads(urlopen('https://ipinfo.io/%s/json' % ip).read())
    if 'asn' in info:
        message = ', ASN: %s' % (info['asn'])
    if 'country' in info:
        message = ', COUNTRY: %s' % (info['country'])
    if 'region' in info:
        message = ', REGION: %s' % (info['region'])
    if 'city' in info:
        message = ', CITY: %s' % (info['city'])
    if 'org' in info:
        message += ' %s' % info['org']
    return message


def format_line(line):
    decoded_line = line.decode('CP866')
    match_local_ip = re.findall(r"192\.168\.\d{1,3}\.\d{1,3}", decoded_line)
    match_ip = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", decoded_line)
    match_miss = re.findall(r"\* {8}\* {8}\*", decoded_line)
    if match_local_ip:
        return f"IP: {match_ip[0]}, ASN: Local"
    elif match_ip:
        return f"IP: {match_ip[0]}" + get_location(match_ip[0])
    elif match_miss:
        return '****'


def traceroute(destination: str):
    route = []
    data = subprocess.check_output(["tracert", destination]).splitlines()
    for line in data:
        formatted_line = format_line(line)
        if formatted_line is not None:
            route.append(formatted_line)
    route = route[1:]
    return route


def main():
    parser = ArgumentParser(description='Trace AS route utility')
    parser.add_argument('destination', type=str, help='ip or domain name')
    args = parser.parse_args()
    i = 1
    for message in traceroute(args.destination):
        print(str(i) + ' ' + message)
        i += 1


if __name__ == '__main__':
    main()
