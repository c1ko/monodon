#!/usr/bin/env python3

import dns.resolver
import string
import time
import copy
import sys
import argparse
import configparser
import sqlite3
import queue
import logging
import threading 

from utils.parser_checks import parser_check_positive
from utils.squat_generator import generate_char_simple, generate_homoglyphs, generate_numbers
from utils.wikipedia_wordlist import generate_wikipedia_wordlist
from utils.tld_generator import TLDGenerator
from utils.utils import dedup

START_TIME = time.time()

parser = argparse.ArgumentParser(description="Search for possible squatting domains")
parser.add_argument("scanword", type=str, help="Which domain name / word to scan (without the TLD)")
parser.add_argument("--config", type=str, default="config.ini", help="Config file to use")
parser.add_argument("--forcetlds", type=str, default=None, nargs="+", help="Override TLDs for all scan modes")
parser.add_argument("--tldfile", type=str, default=None, nargs="?", help="Instead of downloading a fresh copy from publicsuffix.org, use this as a list of all tlds and slds")
parser.add_argument("--threads", type=parser_check_positive, default=5, help="Number of scanthreads to start")
parser.add_argument("--rate", type=parser_check_positive, default=10, help="Scans per second")
parser.add_argument("--nameserver", type=str, nargs="?", default=None, help="DNS server to use")
parser.add_argument("--verbose", default=False, action="store_true", help="Log all DNS queries and errors")

group_scan_modes = parser.add_argument_group("Scan modes")
group_scan_modes.add_argument("--all", default=False, action='store_true', help="Execute all scanning techniques")
group_scan_modes.add_argument("--tlds", default=False, action='store_true', help="Scan all TLDs")
group_scan_modes.add_argument("--slds", default=False, action='store_true', help="Scan all TLDs and known SLDs")
group_scan_modes.add_argument("--homo", default=False, action='store_true', help="Scan homoglyphs")
group_scan_modes.add_argument("--chars", default=False, action='store_true', help="Scan character replacements and additions")
group_scan_modes.add_argument("--numbers", default=False, action='store_true', help="Iterate numbers in the domain name")
group_scan_modes.add_argument("--phishing", default=False, action='store_true', help="Scan phishing wordlist")
group_scan_modes.add_argument("--ccodes", default=False, action='store_true', help="Scan two-letter country codes")
group_scan_modes.add_argument("--wiki",  type=str, nargs="+", help="Scan words from wikipedia lemmas (e.g. 'en:whale')")
group_scan_modes.add_argument("--wordlist", type=str, nargs="?", help="Scan an additional wordlist file")

homo_settings = parser.add_argument_group("homo settings")
homo_settings.add_argument("--homo_tlds", type=str, nargs="+", help="TLDs to scan")

chars_settings = parser.add_argument_group("chars settings")
chars_settings.add_argument("--chars_tlds", type=str, nargs="+", help="TLDs to scan")

numbers_settings = parser.add_argument_group("numbers settings")
numbers_settings.add_argument("--numbers_tlds", type=str, nargs="+", help="TLDs to scan")

phishing_settings = parser.add_argument_group("phishing settings")
phishing_settings.add_argument("--phishing_tlds", type=str, nargs="+", help="TLDs to scan")

phishing_settings = parser.add_argument_group("ccodes settings")
phishing_settings.add_argument("--ccodes_tlds", type=str, nargs="+", help="TLDs to scan")

wiki_settings = parser.add_argument_group("wiki settings")
wiki_settings.add_argument("--wiki_tlds", type=str, nargs="+", help="TLDs to scan")
wiki_settings.add_argument("--wiki_count", type=parser_check_positive, help="Top # of Wikipedia terms to scan")

wordlist_settings = parser.add_argument_group("wordlist settings")
wordlist_settings.add_argument("--wordlist_tlds", type=str, nargs="+", help="TLDs to scan")

args = parser.parse_args()

config = configparser.ConfigParser()
config.read(args.config)

SCANWORD = args.scanword.lower()
glob_scancounter = 0
glob_found_domains = 0
glob_scan_delay = 1.0
glob_scanpool = queue.SimpleQueue()
glob_known_hosts = {}

con = sqlite3.connect(f"{SCANWORD}.db")
cur = con.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS domains (host text, tld text, master text, first_seen text, last_seen text, accepts_anyhost bool)")
con.commit()
con.close()

# Setup logging
logging_datefmt = "%Y-%m-%d %H:%M:%S"
logging_level = logging.DEBUG if args.verbose else logging.INFO

logging.basicConfig(format="%(asctime)s %(message)s", level=logging_level, datefmt=logging_datefmt)

def get_argument(argument, config_section, config_key, **kwargs):
	global config

	# Try argument first
	if argument is not None:
		return argument

	# Try config second
	else:
		try:
			configuration_setting = config[config_section].get(config_key).strip()
			if " " in configuration_setting: # Is an array?
				return configuration_setting.split()
			else:
				return configuration_setting
		except Exception as e:
			logging.warn(e)
			if "default" in kwargs:
				return kwargs["default"]
			else:
				sys.exit(f"Configuration and arguments do not contain information on {config_section} {config_key}")


def load_wordlist_file(filename):
	words = []
	with open(filename, "r") as f:
		for line in f.readlines():
			words += line.lower().split()

	returnlist = dedup(words)
	return returnlist


def scan_host(host, tlds):
	global glob_known_hosts, glob_scanpool
	if host in glob_known_hosts:
		# We cannot remove anything from the queue, so we add all of the tlds that will not already be scanned
		remaining_tlds = [tld for tld in tlds if tld not in glob_known_hosts[host]]
		if len(remaining_tlds) > 0:
			glob_scanpool.put((host, remaining_tlds))
			glob_known_hosts[host] += remaining_tlds
	else:
		glob_known_hosts[host] = tlds
		glob_scanpool.put((host, tlds))


def scan_wordlist(scanword, wordlist, tld_list):
	for word in wordlist:
		scan_host(f"{scanword}{word}", tld_list)
		scan_host(f"{scanword}-{word}", tld_list)
		scan_host(f"{word}{scanword}", tld_list)
		scan_host(f"{word}-{scanword}", tld_list)


class ScanThread(threading.Thread):
	def _touch_domain(self, host, tld):
		try:
			soa_records = self.resolver.resolve(".".join([host, tld]), "SOA")
		except Exception as e:
			logging.debug(e)
			return False

		# Search the SOA records for master names
		master_names = []
		for soa_record in soa_records.response.answer:
			for rdata in soa_record:
				try:
					master_names.append(rdata.mname.to_text())
				except Exception as e:
					logging.debug(e)
					return False

		return list(set(master_names)) # Deduplicate

	def _note_domain(self, host, tld, master_name, accepts_anyhost, first_seen=time.time(), last_seen=time.time()):
		con = sqlite3.connect(f"{SCANWORD}.db")
		cur = con.cursor()
		domain_to_insert = (host, tld, master_name, str(first_seen), str(last_seen), accepts_anyhost)
		sql = ("INSERT INTO domains(host,tld,master,first_seen,last_seen,accepts_anyhost) VALUES (?, ?, ?, ?, ?, ?)")	
		con.execute(sql, domain_to_insert)
		con.commit()
		con.close()


	def scan_tlds(self, to_scan):
		global glob_scancounter, glob_scan_delay, glob_found_domains
		host = to_scan[0]

		logging.debug(f"Scanning {to_scan[0]} on {to_scan[1]}")
		
		for tld in to_scan[1]:
			glob_scancounter += 1
			dns_result = self._touch_domain(host, tld)
			if dns_result:
				logging.warning(f"Found: {host}.{tld} on {dns_result[0]}")
				accepts_anyhost = True if self._touch_domain("jdwqnwqqnwdsauuwuwdnakkkasd", tld) else False
				self._note_domain(host, tld, dns_result[0], accepts_anyhost)
				glob_found_domains += 1

			time.sleep(glob_scan_delay)


	def run(self):
		global glob_scan_delay, glob_scanpool, glob_tlds_to_scan
		while True:
			to_scan = glob_scanpool.get()  # Blocks until item is available
			if to_scan == "STOP": 
				logging.info(f"Scan thread {threading.get_ident()} finished")
				break  # Terminate the thread
			else:
				self.scan_tlds(to_scan)


	def __init__(self, nameserver=None):
		super(ScanThread, self).__init__()
		self.resolver = dns.resolver.Resolver()
		if nameserver:
			self.resolver.nameservers = [nameserver]


class WatchThread(threading.Thread):
	def run(self):
		global glob_scan_delay, glob_scancounter, glob_scanpool, glob_known_hosts, glob_found_domains, START_TIME
		last_scancounter = 0
		i = 0
		while True:
			# Readjust scan delay
			current_scanrate = glob_scancounter-last_scancounter
			if time.time() > START_TIME+5:
				adjustment_factor = current_scanrate / self.target_scanrate
				glob_scan_delay *= adjustment_factor
				glob_scan_delay = max(0.1, glob_scan_delay) # Make sure that the we dont not accidentially DDOS somebody
				glob_scan_delay = min(20, glob_scan_delay) # Make sure that the delay does not occilate to wildly

			# Print current status
			if i%30 == 10 and glob_scancounter > 0:
				domains_to_scan = sum(map(lambda x: len(x), glob_known_hosts.values()))
				remaining_scantime = round(domains_to_scan/(glob_scancounter/(time.time()-START_TIME))/3600, 2)
				logging.info("")
				logging.info(f"Running since {round((time.time()-START_TIME)/3600,2)}h, about {remaining_scantime}h left")
				logging.info(f"Scanned {glob_scancounter} of {domains_to_scan} ({round((glob_scancounter/(domains_to_scan))*100, 2)}%), found {glob_found_domains} domains")
				logging.info(f"Current scanrate is {current_scanrate} scans/sec, scan-delay is {round(glob_scan_delay,2)}s")
				logging.info("")

			last_scancounter = copy.copy(glob_scancounter)
			i += 1
			time.sleep(1)

	def __init__(self, target_scanrate):
		super(WatchThread, self).__init__()
		self.target_scanrate = target_scanrate


tld_gen = TLDGenerator(tldfile=args.tldfile, forcedtlds=args.forcetlds) # Initialize the tld generator

# Start all threads
watch_thread = WatchThread(args.rate)
watch_thread.daemon = True
watch_thread.start()

threadpool = []
for i in range(0, get_argument(args.threads, "GENERAL", "threads")):
	threadpool.append(ScanThread(nameserver=get_argument(args.nameserver, "GENERAL", "nameserver", default=False)))
	threadpool[-1].start()

# Scan all tlds and known slds
if args.all or args.slds:
	logging.info("Scanning tlds and known slds")

	# Split this task into smaller chunks to make it multi-threaded
	tlds_to_scan = tld_gen.generate_tlds("all_tlds_incl_slds")
	for i in range(0, len(tlds_to_scan), 10):
		scan_host(SCANWORD, tlds_to_scan[i:i+10])

# Scan all tlds
elif args.tlds:
	logging.info("Scanning tlds")
	
	# Split this task into smaller chunks to make it multi-threaded
	tlds_to_scan = tld_gen.generate_tlds("all_tlds")
	for i in range(0, len(tlds_to_scan), 10):
		scan_host(SCANWORD, tlds_to_scan[i:i+10])

# Scan for character replacement and addition squatting
if args.all or args.chars:
	logging.info(f"Scanning simple char replacements")

	for host in generate_char_simple(SCANWORD):
		if host != SCANWORD: 
			scan_host(host, tld_gen.generate_tlds(get_argument(args.chars_tlds, "CHARS", "TLDs")))

# Scan homoglyphs
if args.all or args.homo:
	logging.info(f"Scanning homoglyphs")

	for host in generate_homoglyphs(SCANWORD):
		scan_host(host, tld_gen.generate_tlds(get_argument(args.homo_tlds, "HOMO", "TLDs")))

# Scan for all country codes
if args.all or args.ccodes:
	logging.info(f"Scanning country codes")
	scan_wordlist(
		SCANWORD, 
		load_wordlist_file("wordlists/country_codes.txt"), 
		tld_gen.generate_tlds(get_argument(args.ccodes_tlds, "CCODES", "TLDs"))
	)

# Scan often-used phshing wordlist
if args.all or args.phishing:
	logging.info(f"Scanning phishing wordlist")
	scan_wordlist(
		SCANWORD, 
		load_wordlist_file("wordlists/phishing.txt"), 
		tld_gen.generate_tlds(get_argument(args.phishing_tlds, "PHISHING", "TLDs"))
	)

# Scan numbers
if args.all or args.numbers:
	logging.info(f"Scanning numbers")

	for host in generate_numbers(SCANWORD):
		scan_host(host, tld_gen.generate_tlds(get_argument(args.numbers_tlds, "NUMBERS", "TLDs")))

# Scan wikipedia wordlists
if args.all or args.wiki:
	# Generate and scan related wordlist
	lemmas = get_argument(args.wiki, "WIKI", "Lemmas")
	logging.info(f"Generating wikipedia wordlist from lemmas {', '.join(lemmas)}")

	related_terms = {}
	for lemma in lemmas:
		language_code = lemma.split(":")[0]
		title = lemma.split(":")[1]
		for term, relevance in generate_wikipedia_wordlist(title, language_code):
			if term in related_terms:
				related_terms[term] += relevance
			else:
				related_terms[term] = relevance

	sorted_related_terms = sorted(related_terms.items(), key=lambda x: x[1], reverse=True)[:int(get_argument(args.wiki_count, "WIKI", "Count"))]

	scan_wordlist(
		SCANWORD, 
		map(lambda x: x[0], sorted_related_terms), 
		tld_gen.generate_tlds(get_argument(args.wiki_tlds, "WIKI", "TLDs"))
	)

# Scan additional wordlists
if args.all or args.wordlist:
	logging.info(f"Scanning wordlist")
	scan_wordlist(
		SCANWORD,
		load_wordlist_file(get_argument(args.wordlist, "WORDLIST", "Path")),
		tld_gen.generate_tlds(get_argument(args.wordlist_tlds, "WORDLIST", "TLDs"))
	)

logging.warning(f"Scanning {sum(map(lambda x: len(x), glob_known_hosts.values()))} domains...")

for i in range(0, args.threads):
	glob_scanpool.put("STOP")  # Scan threads terminate when fetching this signal

for t in threadpool:
	t.join()

logging.warning("All scans finished")