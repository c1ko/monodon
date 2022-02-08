# monodon
Domain abuse scanner covering domainsquatting and phishing keywords

## Setup
Monodon is a Python 3.7+ programm. To setup on a Linux machine with Python 3.7 or later, take the following steps.

```
git clone https://github.com/c1ko/monodon.git
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

## Before usage
Monodon uses the SOA record of domains to check if is registered. The presence of this record definitly means it is registered. If the SOA flag is missing, the domain can still be registered!

Monodon will generate a DNS query for every domain to check. Public nameservers like `8.8.8.8`, `8.8.4.4`, and `9.9.9.9` can sustain 20 queries and more per second without throtteling. You can control the rate of queries using the `--rate` argument. By default, `--rate` is set to 10 queries per second.

## Usage
You can configure monodon using the command line and the config.ini file. Some options can only be set in one of these sources.
To make use of monodon, you need to supply at least one scan mode and the scanword. The scanword usually is the name of your brand, or the host portion of the domain you want to find squats of.

```
(venv) [mono@mono monodon]$ ./monodon.py --tlds monodon
2022-02-07 22:05:00,884 Loaded 9211 domains from publicsuffix.org
2022-02-07 22:05:00,885 Scanning tlds
2022-02-07 22:05:00,897 Scanning 1495 domains...
2022-02-07 22:05:08,967 Found: monodon.cn on dns19.hichina.com.
2022-02-07 22:05:08,971 Found: monodon.cz on mbox.netro.cz.
2022-02-07 22:05:09,482 Found: monodon.co on ns53.domaincontrol.com.
2022-02-07 22:05:09,504 Found: monodon.de on root-dns.netcup.net.
2022-02-07 22:05:09,947 Found: monodon.com on ns1.namefind.com.
2022-02-07 22:05:10,894 
2022-02-07 22:05:10,894 Running since 0.0h, about 0.06h left
2022-02-07 22:05:10,894 Scanned 74 of 1495 (4.95%), found 5 domains
2022-02-07 22:05:10,894 Current scanrate is 9 scans/sec, scan-delay is 0.45s
```

### Scan modes
Monodon supports various scan modes.
```
  --all                 Execute all scanning techniques
  --tlds                Scan all tlds
  --slds                Scan all tlds and known slds
  --homo                Scan homoglyphs
  --chars               Scan character replacements and additions
  --numbers             Iterate numbers in the domain name
  --phishing            Scan phishing wordlist
  --ccodes              Scan two-letter country codes
  --wiki                Scan Wikipedia generated related word lists
  --wordlist            Scan wordlists defined in config file
```

`--all` Use all scanning techniques mentioned below. This can be a lengthy endeavor, depending on how many wikipedia terms will be scannend, which tlds are scanned, and how long the scanword ist. Monodon can easily generate 1 million or more domains to scan.

`--tlds` Scan all registered top-level domains. Monodon downloads a fresh list of tlds from https://publicsuffix.org/list every time the command is run. If you do not want to download a fresh list, you can supply the `--tldfile` flag to supply a custom tld file to use.

`--slds` Scan all registered top-level domains and all second level domains known to publicsuffix.org. Like for `--tld` you can override the list with the `--tldfile` option. 

`--homo` Generate homoglyphic variants of the supplied scanword. Scanned hosts for "monodon" would be "m0nodon" or "monoton".

`--chars` Insert and remove chars from within the scanword. Scanned hosts for "monodon" would for example be "mondon" or "monodono". 

`--numbers` Count numbers up and down in the domain name. Scanned hosts for "monodon24" would be "monodon42" or "monodon02".

`--phishing` Use the list of common phishing suffixes and prefixes to scan. Scanned hosts for "monodon" would be "monodon-online" or "wwwmonodon". 

`--ccodes` Add ISO-3166 country codes to the host. Scanned hosts for "monodon" would be "monodon-us" or "usmonodon".

`--wiki` Use wikipedia to generate term-related wordlists to scan. Monodon downloads the wikipedia article for a the given term(s) and generates a list of the most common words. You can either use `--wikiterms` to supply the Wikipedia pages to use, or configure them in the config file. In the config file, you can also set the number of words to scan (default ist 750). 

```
(venv) [mono@mono monodon]$ ./monodon.py monodon --wiki --wikiterms whale monodon tooth 
2022-02-07 22:34:43,261 Loaded 9211 domains from publicsuffix.org
2022-02-07 22:34:43,262 Scanning generated wikipedia wordlist
2022-02-07 22:34:44,380 Scanning 15000 domains..
```

For most scan modes the scanned tlds can be set in the config.ini file. Default are often-abused tlds, but you can replace this by top 5, top 15, all, or specific tlds. You can also use `--forcetlds` to execute all scans on a specific set of tlds.

### Scan settings

`--rate` Scans executed per second. This rate can be exceeded for short periods of time, but will auto-adjust.

`--threads` Number of scan threads to use. Especially with slow nameservers, a higher number of threads is adviced. The standard 5 threads is usually a good choice.

`--config` Load a different config file than the standard config.ini.
