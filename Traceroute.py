import argparse
import re
import subprocess
import json
import urllib.request
import ipwhois.exceptions
from ipwhois import IPWhois


def start_tracing(ip):
    try:
        peaks = perform_a_trace(ip)
        if len(peaks) == 0:
            raise Exception('Возникла ошибка, проверьте ip')
        print_first()
        for number, node in enumerate(peaks):
            # result = get_autonomous_system(node)
            result = whois(node)
            print_line(number, node, result)
    except Exception as e:
        print(str(e))


def perform_a_trace(ip):
    traceroute = get_traceroute(ip)
    ips = parse_traceroute(traceroute)
    return ips


def get_traceroute(ip):
    traceroute = subprocess.Popen(['tracert', '-d', ip], stdout=subprocess.PIPE)
    # -d - Не выводить имена сетевых узлов, только IP (сокращает время трассировки)
    return traceroute.communicate()[0].decode('866')  # communicate() returns a tuple (stdoutdata, stderrdata).


def parse_traceroute(traceroute):
    lines = traceroute.split('\n')
    result = []
    for line in lines[2:]:
        ip = re.search(re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'), line)
        if ip is not None:
            result.append(ip.group(0))
    return result


def parse_whois_result(result: dict):
    asn = result['asn'] + ' '
    country = result['asn_country_code'] + ' ' if result['asn_country_code'] is not None else ''
    if result['asn'] == "NA" or result['asn_description'] is None:
        provider = '-'
        return asn, country, provider
    if re.search(re.compile(r'\"(.*?)\"|\'(.*?)\''), result['asn_description']) is not None:
        provider = re.search(re.compile(r'\"(.*?)\"|\'(.*?)\''), result['asn_description']).group()
        return asn, country, provider
    if re.search(re.compile(r'\"(.*?)\"|\'(.*?)\''), '"' + result['asn_description'] + '"') is not None:
        provider = re.search(re.compile(r'\"(.*?)\"|\'(.*?)\''), '"' + result['asn_description'] + '"').group()
        return asn, country, provider


def whois(ip_address: str):
    if ip_address == '*':
        return 'No data'
    try:
        result = IPWhois(ip_address)
    except ipwhois.exceptions.IPDefinedError:
        return 'No data'
    return parse_whois_result(result.lookup_whois())


def print_line(number, ip, result):
    if result == "No data":
        print(f'{number:<{5}}'
              f'{ip:<{20}}'
              f'{"-":<{10}}'
              f'{"-":<{10}}'
              f'{"-"}')
        return
    print(f'{number:<{5}}'
          f'{ip:<{20}}'
          f'{result[0]:<{10}}'
          f'{result[1]:<{10}}'
          f'{result[2]}')


def print_first():
    print('№' + ' ' * 4 +
          'IP' + ' ' * 19 +
          'AS' + ' ' * 8 +
          'Country' + ' ' * 3 +
          'Provider')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("ip")
    args = parser.parse_args()

    start_tracing(args.ip)

