#!/usr/bin/env python3

import argparse
import sqlite3

parser = argparse.ArgumentParser(description="Dump the domainsquatting database")
parser.add_argument("dbfile", type=str, help="Squatting database to load")
parser.add_argument("--filter", nargs="+", type=str, help="Filter master names containing these strings")
parser.add_argument("--csv", action="store_true", help="Output as csv")
args = parser.parse_args()

# Setup the database
con = sqlite3.connect(args.dbfile)
cur = con.cursor()

def print_csv(row):
	print(f"{row[0]}.{row[1]};{row[2]};{row[-1]}")

def print_plain(row):
	print(f"{row[0]}.{row[1]}\t{row[2]}\t{row[-1]}")

for row in cur.execute("SELECT * FROM domains"):
	filtered = False
	if args.filter:
		for f in args.filter:
			if f in row[2]:
				filtered = True
				break

	if not filtered:
		if args.csv:
			print_csv(row)
		else:
			print_plain(row)

con.close()