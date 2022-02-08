#!/usr/bin/env python3

import argparse
import sqlite3
import time
import dns.resolver

parser = argparse.ArgumentParser(description="Dump the domainsquatting database")
parser.add_argument("dbfile", type=str, help="Squatting database to load")
parser.add_argument("--slowness", nargs="?", type=float, default=1, help="Speed factor to reduce DOS potential")
parser.add_argument("--nsfilter", nargs="?", default=None, type=str, help="Filter out certain nameservers")
args = parser.parse_args()

# Setup the database
con = sqlite3.connect(args.dbfile)
cur = con.cursor()

# Load domain protection nameservers
domain_protection_ns = []
with open("domain_protection_nameservers.txt", "r") as f:
	for line in f.readlines():
		line = line.strip()
		if line != "": 
			domain_protection_ns.append(line.strip())

def check_domain_protection(domain):
	global domain_protection_ns

	for ns in domain_protection_ns:
		if ns in domain["ns"]:
			return True

	return False


def check_record(domain, record):
	try:
		q = dns.resolver.resolve(".".join([domain["host"], domain["tld"]]), record)
		for rdata in q:
			return rdata.to_text()
	except Exception as e:
		return None

for row in cur.execute("SELECT * FROM domains"):
	# Filter out certain nameservers
	if args.nsfilter is not None:
		if args.nsfilter in row[2]:
			continue

	domain = {
		"host": row[0],
		"tld": row[1],
		"ns": row[2],
	}

	domain["protected"] = check_domain_protection(domain)
	domain["A"] = check_record(domain, "A")
	domain["AAAA"] = check_record(domain, "AAAA")
	domain["MX"] = check_record(domain, "MX")

	print(domain)

	time.sleep(args.slowness)

con.close()