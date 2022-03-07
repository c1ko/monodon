# 🦷 monodon 🐋
__Domain abuse scanner covering domainsquatting and phishing keywords.__

## Setup
Monodon is a Python 3.7+ programm. To setup on a Linux machine with Python 3.7 or later, take the following steps.

```
git clone https://github.com/c1ko/monodon.git
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

To test the script, run a simple scan and abort it at any time:
```
./monodon.py --chars --phishing --rate 2 --threads 2 monodon
```

## Before usage
Monodon uses the SOA record of domains to check if is registered. The presence of this record definitly means it is registered. If the SOA flag is missing, the domain can still be registered!

Monodon will generate a DNS query for every domain to check. Public nameservers like `8.8.8.8`, `8.8.4.4`, and `9.9.9.9` can sustain 20 queries and more per second without throtteling. Set a nameserver using the `--nameserver` setting. Otherwise monodon will use your systems nameserver. You can control the rate of queries using the `--rate` argument. By default, `--rate` is set to 10 queries per second. 

If you want to create more than 10 queries per second and thread, use the `--unsafe` keyword. This safeguard protects from unwanted DOS attacks on public DNS servers. To not generate any actual DNS queries, use the `--simulate` argument. 

## Usage
You can configure most settings using the command line and the config.ini file. Some options can only be set as an argument.
To make use of monodon, you need to supply at least one scan mode and the scanword. The scanword usually is the name of your brand, or the host portion of the domain you want to find squats of. 

```
(venv) $ ./monodon.py --tlds monodon
Loaded 9211 domains from publicsuffix.org
Scanning tlds
Scanning 1495 domains...
Found: monodon.cn on dns19.hichina.com.
Found: monodon.cz on mbox.netro.cz.
Found: monodon.co on ns53.domaincontrol.com.
Found: monodon.de on root-dns.netcup.net.
Found: monodon.com on ns1.namefind.com.
 
Running since 0.0h, about 0.06h left
Scanned 74 of 1495 (4.95%), found 5 domains
Current scanrate is 9 scans/sec, scan-delay is 0.45s
```

### Result format
Monodon documents all results in an sqlite database called $SCANWORD.db in the monodon directory. You can dump the contents of the database using the `dump_db.py` script from the project folder.  

### Scan modes
Monodon supports various scan modes.
```
  --all                      Execute all scanning techniques
  --tlds                     Scan all TLDs
  --slds                     Scan all TLDs and known SLDs
  --homo                     Scan homoglyphs
  --chars                    Scan character replacements and additions
  --numbers                  Iterate numbers in the domain name
  --phishing                 Scan phishing wordlist
  --ccodes                   Scan two-letter country codes
  --wiki WIKI [WIKI ...]     Scan words from wikipedia lemmas (e.g. 'en:whale')
  --wordlist [WORDLIST]      Scan an additional wordlist file
```

`--all` Use all scanning techniques mentioned below. This can be a lengthy endeavor, depending on how many wikipedia terms will be scannend, which tlds are scanned, and how long the scanword ist. Monodon can easily generate 1 million or more domains to scan.

`--tlds` Scan all registered top-level domains. Monodon downloads a fresh list of tlds from https://publicsuffix.org/list every time the command is run. If you do not want to download a fresh list, you can supply the `--tldfile` flag to supply a custom tld file to use.

`--slds` Scan all registered top-level domains and all second level domains known to publicsuffix.org. Like for `--tld` you can override the list with the `--tldfile` option. Monodon will automatically check if the tld accepts any hostname, like many of the AWS domains do, and document the result in the database.

`--homo` Generate homoglyphic variants of the supplied scanword. Scanned hosts for "monodon" would be "m0nodon" or "monoton".

`--chars` Insert and remove chars from within the scanword. Scanned hosts for "monodon" would for example be "mondon" or "monodono". 

`--numbers` Count numbers up and down in the domain name. Scanned hosts for "monodon24" would be "monodon42" or "monodon02".

`--phishing` Use the list of common phishing suffixes and prefixes to scan. Scanned hosts for "monodon" would be "monodon-online" or "wwwmonodon". 

`--ccodes` Add ISO-3166 country codes to the host. Scanned hosts for "monodon" would be "monodon-us" or "usmonodon".

`--wiki` Use wikipedia to generate term-related wordlists to scan. Monodon downloads the wikipedia article for a the given term(s) and generates a list of the most common words. You can supply lemmas in the config file or via the command line. Include the wikipedia language shorthand (e.g. "en" or "de"), seperated by a colon. To configure the number of used terms, use the `--wiki_count` option. 

```
(venv) $ ./monodon.py --wiki en:whale de:narwal monodon 
Loaded 9211 domains from publicsuffix.org
Scanning generated wikipedia wordlist
Scanning 15000 domains..
```

If you only want to check which words were generated (and what rating they have), use the `--wiki_test` flag. No wikipedia queries will be executed in this case.

```
(venv) $ ./monodon.py --wiki en:whale de:narwal --wiki_test --wiki_count 15  monodon
Loaded 9211 domains from publicsuffix.org
Generating wikipedia wordlist from lemmas en:whale, de:narwal
('the', 462), ('and', 240), ('whales', 114), ('are', 112), ('der', 107), ('die', 98), ('they', 91), ('und', 87), ('whale', 79), ('for', 67), ('their', 65), ('have', 59), ('which', 55), ('von', 51), ('that', 45)
```

`--wordlist` Scan an additional wordlist file, supplied as an argument or config.ini option.

For most scan modes the scanned tlds can be set in the config.ini file. These defaults can be overriden using the `_tld` option for each mode. You can either supply direct tlds like "de" or "com", or prefiltered lists: "top5", "top15", "abused", "all_tlds". You can also use `--forcetlds` to execute all scans on a specific set of tlds, no matter what the config says.

### General settings

`--rate` Scans executed per second. This rate can be exceeded for short periods of time, but will auto-adjust.

`--threads` Number of scan threads to use. Especially with slow nameservers, a higher number of threads is adviced. The standard 5 threads is usually a good choice.

`--simulate` Simulate the DNS queries instead of actually executing them. Good for testing purposes.

`--verbose` Log each DNS query, giving greater detail on what is going on.

`--nameserver` Use another than the system's nameserver to scan.

`--config` Load a different config file than the standard config.ini.

`--unsafe` Allow more than 10 queries per scanning thread.

`--unregistered` Experimental feature: Search for unregistered domains instead of registered domains.

`--timeout` How long should monodon wait for a DNS server to answer. Default is 5 seconds.

`--retries` How often should monodon retry in case of a timeout. Default is once.

## Examples

Scan all tlds for the exact hostname:
```
(venv) $ ./monodon.py --tlds monodon 
Loaded 9211 domains from publicsuffix.org
Scanning tlds
Scanning 1495 domains...
```

Scan for char replacements and homoglyphic replacements on the top 5 TLDs:
```
(venv) $ ./monodon.py --chars --chars_tlds top5 --homo_tlds top5 --homo monodon
Loaded 9211 domains from publicsuffix.org
Scanning simple char replacements
Scanning homoglyphs
Scanning 2890 domains...
Found: moodon.com on ns23.domaincontrol.com.
Found: mondon.com on ns1.cornut.fr.
...
```

Scan for number and phishing variants only on the ".de" domain, using a custom nameserver and a higher rate:
```
(venv) $ ./monodon.py --numbers --phishing --forcetlds de --rate 15 --nameserver 9.9.9.9 monodon24
```

Scan for the top 20 words from Wikipedia articles:

```
(venv) $ ./monodon.py --wiki en:whale de:narwal --wiki_count 20  monodon
Loaded 9211 domains from publicsuffix.org
Generating wikipedia wordlist from lemmas en:whale, de:narwal
```
