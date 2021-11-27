#!/usr/bin/env python3

import argparse
import logging
import json
from collections import defaultdict
from datetime import datetime

# Custom logger
logger = logging.getLogger(__name__)

# Constants for color display
HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKCYAN = '\033[96m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'


def header(title):
    """
    Display a header to separate different statistics
    """
    print(BOLD + HEADER + UNDERLINE + title + ENDC)


class Graph(object):

    @classmethod
    def display(cls, data, title, unit='hits', show_percents=True, top=None):
        """
        Displays an ASCII bar graph in the console, one bar per line
        :param data: Dictionary
        :type data: dict[str,int|float]
        :param title: Header to display
        :param unit: Unit of the values, if the unit is "bytes", it will be formatted automatically
        :type unit: str
        :param show_percents: Display percentage the bar represents at the end of each bar
        :param top: Limit the number of entries to display
        :type top: int|None
        """

        header(title + (f" - Top {top}" if top is not None else ""))

        sum_values = sum(data.values())
        # If it's top, we truncate the list
        if top is not None:
            data = data[0:top]
        max_value = max(data.values())

        # We get the length of the longest label to be able to offset all items in the list
        label_max_length = max([len(str(label)) for label in data.keys()])
        for key, value in data.items():
            bar_size = value * 100 / max_value
            bar_string = '█' * int(bar_size)
            percent_string = ""
            if show_percents:
                percent = value * 100 / sum_values
                percent_string = f"/ {percent:.2f}%"
            formatted_value = f"{value} {unit}"

            print(f"    {OKBLUE + str(key).ljust(label_max_length) + ENDC}|{bar_string} :"
                  f" {OKGREEN}{formatted_value}{ENDC}{percent_string}")


class TopList(object):

    @classmethod
    def display(cls, data, title, unit='hits', top=10):
        """
        Displays a list of values in the console, one per line
        :param data:
        :type data: dict[Any,int|float]
        :param title: Header to display
        :param unit: Unit of the values, if the unit is "bytes", it will be formatted automatically
        :type unit: str
        :param top: Reduce the number of entries to specified number
        :type top: int
        """
        data = sorted(data.items(), key=lambda x: x[1], reverse=True)[0:top]
        header(title + f" - Top {top}" if top is not None else "")

        for index, value in enumerate(data):
            if isinstance(value[1], float):
                formatted_value = f"{value[1]:.2f} {unit}"
            else:
                formatted_value = f"{value[1]} {unit}"

            print(f"    #{index + 1}: {value[0]} {OKGREEN}{formatted_value}{ENDC}")


def get_stats(data):
    # Initialize variables to hold statistics
    hits_per_page = defaultdict(int)
    bytes_per_ip = defaultdict(float)
    hits_per_response = defaultdict(int)
    hits_per_os = defaultdict(int)
    hits_per_time = defaultdict(int)

    # For each entry, an entry corresponds to a log line as a dict
    for entry in data:
        # Count hits per URL
        hits_per_page[entry['url']] += 1
        # Sum MegaBytes per IP address
        bytes_per_ip[entry['remote_ip']] += entry['bytes'] / 1024 / 1024
        # Count hits per HTTP response code
        hits_per_response[entry['response']] += 1
        # Count hits per detected OS
        hits_per_os[entry['system_agent']] += 1
        # Count hits per hour
        time = datetime.strptime(entry['time'], "%d/%b/%Y:%H:%M:%S %z")
        hits_per_time[f"{time.hour:02d}:00-{time.hour + 1:02d}:00"] += 1

    # Display the stats
    TopList.display(hits_per_page, 'Hits per page')
    TopList.display(bytes_per_ip, 'Megabytes per IP', unit="MB")
    Graph.display(hits_per_response, 'Response codes')
    TopList.display(hits_per_os, 'Hits per OS')

    # Sort dictionary by key (time range)
    hits_per_time = dict(sorted(hits_per_time.items(), key=lambda x: x[0]))
    Graph.display(hits_per_time, 'Hits per time range')

    # Totals
    header("Stats")
    print(f"    Total hits: {len(data)}")
    print(f"    Total traffic: {sum(bytes_per_ip.values()) / 1024:.2f}GB")
    print(f"    Different visitors: {len(bytes_per_ip.keys())}")
    print(f"    Different URLs visited: {len(hits_per_page.keys())}")


def generate_stats(json_log_file_name):
    """
    Generate and display stats
    :param json_log_file_name: JSON file created by the `generate_json.py` script
    """
    with open(json_log_file_name, 'r') as json_log_file:
        get_stats(json.load(json_log_file))


def main():
    parser = argparse.ArgumentParser(description="Tool to parse apache logs")

    parser.add_argument(dest='json_file', type=argparse.FileType('r'),
                        help="Input apache log input_files")

    args = parser.parse_args()

    generate_stats(args.json_file.name)


if __name__ == '__main__':
    main()
