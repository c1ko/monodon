import logging
import requests

class TLDGenerator():
	def _load_tld_file(self, tld_file):
		with open(tld_file, "r") as f:
			return self._load_raw_tlds(f.read())

	def _load_raw_tlds(self, raw_tld_list):
		# Loads a list of top or n-th level domains
		returnlist = []

		for line in raw_tld_list.split("\n"):
			line = line.strip() # Trim whitespaces
			if line.startswith("/"): continue # Ignore comments
			elif line == "": continue # Ignore empty lines

			if line.startswith("*"): line = line[1:] # Remove leading wildcards
			if line.startswith("!"): line = line[1:] # Remove leading exclamation
			
			# Remove all leading dots
			while line.startswith("."):
				line = line[1:]
			
			returnlist.append(line.lower().strip())

		return returnlist

	def generate_tlds(self, configuration_string):
		out_tlds = []

		if self.forcedtlds:
			return self.forcedtlds

		desired_tlds = configuration_string.split()
		for desired_tld in desired_tlds:
			if desired_tld == "all_tlds":
				out_tlds += self.ALL_TLDS
			elif desired_tld == "all_tlds_incl_slds":
				out_tlds += self.ALL_TLDS_INCL_SLDS
			elif desired_tld == "abused":
				out_tlds += self.ABUSED_TLDS
			elif desired_tld == "top5":
				out_tlds += self.TOP5_TLDS
			elif desired_tld == "top15":
				out_tlds += self.TOP15_TLDS
			elif desired_tld in ALL_TLDS_INCL_SLDS:
				out_tlds += desired_tld
			else:
				logging.warn(f"Top-level-domain .{desired_tld} is not public, check if typo. Scanning it anyway.")

		return out_tlds

	def __init__(self, tldfile=None, forcedtlds=None):
		self.forcedtlds = forcedtlds

		if tldfile:
			self.ALL_TLDS_INCL_SLDS = self._load_tld_file(args.tldfile)
		elif forcedtlds:
			return # No need to load any files, domains are forced anyway
		else:	
			raw_all_sdls = requests.get("https://publicsuffix.org/list/public_suffix_list.dat").text
			self.ALL_TLDS_INCL_SLDS = self._load_raw_tlds(raw_all_sdls)
			logging.info(f"Loaded {len(self.ALL_TLDS_INCL_SLDS)} domains from publicsuffix.org")

		# Filter for a list that only contain tlds
		self.ALL_TLDS = filter(lambda x: not "." in x, self.ALL_TLDS_INCL_SLDS)

		# Load the top abused and top5 tlds
		self.ABUSED_TLDS = self._load_tld_file("tlds/abused.txt")
		self.TOP5_TLDS = self._load_tld_file("tlds/top5.txt")
		self.TOP15_TLDS = self._load_tld_file("tlds/top15.txt")