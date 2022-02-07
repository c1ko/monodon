import string

def generate_char_simple(scanword):
	# Character ommission
	for i in range(len(scanword)):
		yield scanword[:i] + scanword[i+1:]

	# Character repeat
	for i in range(len(scanword)):
		yield scanword[:i] + scanword[i]*2 + scanword[i+1:]

	# Swap adjacent characters
	for i in range(len(scanword)-1):
		yield scanword[:i] + scanword[i+1] + scanword[i] + scanword[i+1:]

	# Insert dashes
	for i in range(1, len(scanword)-1):
		yield scanword[:i] + "-" + scanword[i:]
		
	# Replace one character by dash
	for i in range(1, len(scanword)-1):
		yield scanword[:i] + "-" + scanword[i+1:]

	# Replace all letters once
	for i in range(len(scanword)):
		for repl in string.ascii_lowercase + string.digits:
			yield scanword[:i] + repl + scanword[i+1:]

	# Insert one char
	for i in range(len(scanword)+1):
		for repl in string.ascii_lowercase + string.digits:
			yield scanword[:i] + repl + scanword[i:]

def _load_homoglyphs(similar_chars_file):
	# Currently only loads important homoglypes marked with "!"
	
	homoglyphs = {}
	
	with open(similar_chars_file, "r") as f:
		for line in f.readlines():
			line = line.strip()
			if "#" in line or line == "" or "!" not in line: continue # Skip comments

			# Build the index
			for char in line.split():
				if char not in homoglyphs and char != "!":
					homoglyphs[char] = []

			# Add all chars
			for char_index in line.split():
				for char_add in line.split():
					if char_index != char_add and char_index != "!" and char_add != "!":
						homoglyphs[char_index].append(char_add)

	return homoglyphs


def _count_up(combination_bitmask, current_bitmask):
	while combination_bitmask != current_bitmask:
		for i in range(len(combination_bitmask)):
			if current_bitmask[i] < combination_bitmask[i]:
				current_bitmask = [0]*i + [current_bitmask[i]+1] + current_bitmask[i+1:] # Increase current index and nullify all before
				yield current_bitmask


def generate_homoglyphs(scanword):
	homoglyphs = _load_homoglyphs("wordlists/similar_chars.txt")
	homoglyph_tree = [] 

	# Build a 2D tree of possible replacements
	for char in scanword:
		if char in homoglyphs:
			homoglyph_tree.append([char]+homoglyphs[char])
		else:
			homoglyph_tree.append([char])

	# Build a bitmap how many replacements are there per char
	combination_bitmask = []
	for char in homoglyph_tree:
		combination_bitmask.append(len(char)-1)

	# Iterate all combinations
	current_bitmask = [0]*len(combination_bitmask)

	for current_bitmask in _count_up(combination_bitmask, current_bitmask):
		out = ""
		for i in range(len(current_bitmask)):
			out += homoglyph_tree[i][current_bitmask[i]]
		yield out


def _iterate_numbers(number_tree):
	current_number_tree = []

	for char in number_tree:
		if type(n) == int:
			current_number_tree.append(0)
		else:
			current_number_tree.append(char)

	for i, char in enumerate(current_number_tree):
		if type(char) == str: 
			continue

		elif type(char) == int:
			if char < int("9"*len(number_tree[i])):
				current_number_tree = current_number_tree[:i]


def generate_numbers(scanword):
	# Count numbers in the word
	contained_numbers = 0
	for char in scanword:
		if char in string.digits:
			contained_numbers += 1

	if contained_numbers > 0:
		for i in range(0, int("9"*contained_numbers)+1):
			current_number = str(i).zfill(contained_numbers)

			outword = ""
			index = 0
			for char in scanword:
				if char in string.digits:
					outword += current_number[index]
					index += 1
				else:
					outword += char

			yield outword