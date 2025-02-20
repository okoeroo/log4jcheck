# Log4j CVE-2021-44228 checker

Revamped version.


Friday 10 December 2021 a new Proof-of-Concept [1] addressing a Remote code Execution (RCE) vulnerability in the Java library 'log4j' [2] was published. This vulnerability has not been disclosed to the developers of the software upfront. The vulnerability is being tracked as CVE-2021-44228 [3].

## Origin
I took the exampels online, mixed it with ideas from others out comes this version.

## Checks
This version assumes that outbound DNS is allowed. This is an indication on where a vulnerable system is located. The DNS query carriers the information about the vulnerable system.

## DISCLAIMER
Note that the script only performs two specific checks: *User Agent* and *HTTP GET request*. This will cause false negatives in cases where other headers, specific input fields, etcetera need to be targeted to trigger the vulnerability. Feel free to add extra checks to the script.

## Setting up a DNS server

First, we need a subdomain that we can use to receive incoming DNS requests. In this case we use the zone `log4jdnsreq.cyberz.nl` and we deploy our script on `log4jchecker.cyberz.nl`. Configure a DNS entry as follows:

```
log4jdnsreq 3600 IN  NS log4jchecker.cyberz.nl.
```

We now set up a BIND DNS server on a Debian system using `apt install bind9` and add the following to the `/etc/bind/named.conf.options` file:

```
	recursion no;
    allow-transfer { none; };
```

This disables recusing as we do not want to run an open DNS server. Configure logging in `/etc/bind/named.conf.local` by adding the following configuration:

```
logging {
	channel querylog {
		file "/var/log/named/query.log";
		severity debug 3;
		print-time yes;
	};
	category queries { querylog;};
};
```
Don't forget to touch `/var/log/named/query.log`, chown it to `bind:bind`, and restart BIND using `systemctl restart bind9`. Check if the logging works by performing a DNS query for `xyz.log4jdnsreq.cyberz.nl`. One or more queries should show up in `/var/log/named/query.log`.

## Running the script

Install any Python dependencies using `pip install -r requirements.txt`. Edit the script to change the following line to the DNS zone you configured:

```
HOSTNAME = "log4jdnsreq.cyberz.nl"
```

You can now run the script using the following syntax:

```
python3 log4jcheck.py --target https://www.cyberz.nl --timeout 10
```

## Help
```
usage: log4jcheck.py [-h] [--reply-fqdn REPLYFQDN] [--target TARGET] [--timeout TIMEOUT]

optional arguments:
  -h, --help            show this help message and exit
  --reply-fqdn REPLYFQDN
                        Reply FQDN
  --target TARGET       Target host to examine
  --timeout TIMEOUT     Timeout
```


## License

Log4jcheck is open-sourced software licensed under the MIT license.

[1]: https://github.com/tangxiaofeng7/apache-log4j-poc
[2]: https://logging.apache.org/log4j/2.x/
[3]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228,==
