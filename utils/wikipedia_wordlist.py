import requests
import json
import string

def generate_wikipedia_wordlist(title, language_code):
	r = requests.get(f"https://{language_code}.wikipedia.org/w/api.php?action=query&format=json&titles={title}&prop=extracts&explaintext")
	try:
		extract = list(r.json()["query"]["pages"].values())[0]["extract"]
	except KeyError:
		raise Exception("Wikipedia article not found")

	relevant_words = {}

	for word in extract.split():
		word = word.strip(" -")
		word = word.lower()
		
		if len(word) <= 2: continue
		
		invalid_char = False
		for letter in word:
			if letter not in list(string.ascii_letters) + list(string.digits) + ["-", "ä", "ü", "ö"]:
				invalid_char = True
				break
		if invalid_char: continue

		if word in relevant_words:
			relevant_words[word] += 1
		else:
			relevant_words[word] = 1

	sorted_words = sorted(relevant_words.items(), key=lambda x: x[1], reverse=True)
	return sorted_words