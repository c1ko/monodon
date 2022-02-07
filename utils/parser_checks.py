import argparse

def parser_check_threads(value):
	value = int(value)
	if value <= 0:
		raise argparse.ArgumentTypeError(f"Invalid thread count: {value}")
	elif value > 64:
		raise argparse.ArgumentTypeError(f"Maximum thread count is 64")
	return value

def parser_check_rate(value):
	value = int(value)
	if value <= 0:
		raise argparse.ArgumentTypeError(f"Invalid target rate: {value}")
	return value	