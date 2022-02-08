import argparse

def parser_check_positive(value):
	value = int(value)
	if value <= 0:
		raise argparse.ArgumentTypeError(f"Invalid option: {value}")
	return value