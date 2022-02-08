#!/usr/bin/env python3

import argparse
import sqlite3
import time
import dns.resolver

parser = argparse.ArgumentParser(description="Dump the domainsquatting database")
parser.add_argument("dbfile", type=str, help="Squatting database to load")
parser.add_argument("--slowness", nargs="?", type=float, default=1, help="Speed factor to reduce DOS potential")
parser.add_argument("--filter", nargs="?", type=str, default=1, help="Speed factor to reduce DOS potential")
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

def set_verdict(domain, verdict):
	domain["continue_scanning"] = verdict["continue_scanning"]
	domain["verdict"].append(verdict["verdict"])
	return domain

def check_domain_protection(domain):
	global domain_protection_ns

	for ns in domain_protection_ns:
		if ns in domain["ns"]:
			return True

	return False


def check_a_record(domain):
	try:
		q = dns.resolver.resolve(".".join([domain["host"], domain["tld"]]), "A")
		for rdata in q:
			return rdata.to_text()
	except Exception as e:
		return None


def check_aaaa_record(domain):
	try:
		q = dns.resolver.resolve(".".join([domain["host"], domain["tld"]]), "AAAA")
		for rdata in q:
			return rdata.to_text()
	except Exception as e:
		return None


def check_mx_record(domain):
	try:
		q = dns.resolver.resolve(".".join([domain["host"], domain["tld"]]), "MX")
		for rdata in q:
			return rdata.to_text()
	except Exception as e:
		return None


all_results = []
for row in cur.execute("SELECT * FROM domains"):
	domain = {
		"host": row[0],
		"tld": row[1],
		"ns": row[2],
	}

	domain["protected"] = check_domain_protection(domain)
	domain["A"] = check_a_record(domain)
	domain["AAAA"] = check_aaaa_record(domain)
	domain["MX"] = check_mx_record(domain)

	print(domain)

	time.sleep(args.slowness)

con.close()