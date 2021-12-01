#!/usr/bin/env python3
import argparse
import re
import logging
import json

logger = logging.getLogger(__name__)

# Log use CLF: Common Log Format
# LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"" combined

# - %h	Remote hostname. Will log the IP address if HostnameLookups is set to Off, which is the default.
# If it logs the hostname for only a few hosts, you probably have access control directives mentioning them by name
REMOTE_HOSTNAME_RE = r"(\d+\.\d+\.\d+\.\d+)"
# - %l Remote logname (from identd, if supplied).
# This will return a dash unless mod_ident is present and IdentityCheck is set On.
REMOTE_LOGNAME_RE = r"(-)"
# - %u Remote user if the request was authenticated. May be bogus if return status (%s) is 401 (unauthorized).
REMOTE_USER_RE = r"(-)"
# - %t Time the request was received, in the format [18/Sep/2011:19:18:28 -0400].
# The last number indicates the timezone offset from GMT
TIME_RE = r"\[([^\]]+)\]"
# - %r First line of request.
REQUEST_RE = r'"([^\"]+)"'
# - %>s Status. For requests that have been internally redirected, this is the status of the original request.
# Use %>s for the final status.
STATUS_RE = r"(\d+)"
# - %b Size of response in bytes, excluding HTTP headers.
# in CLF format, i.e. a '-' rather than a 0 when no bytes are sent.
BYTES_SIZE_RE = r"(\d+|\-)"
# - Referer
REFERER_RE = r'"([^\"]+)"'
# - User-agent
USER_AGENT_RE = r'"([^\"]+)"'

# Put the pieces in the right order as per Apache configuration
LOG_LINE_PATTERN = " ".join([REMOTE_HOSTNAME_RE,
                             REMOTE_LOGNAME_RE,
                             REMOTE_USER_RE,
                             TIME_RE,
                             REQUEST_RE,
                             STATUS_RE,
                             BYTES_SIZE_RE,
                             REFERER_RE,
                             USER_AGENT_RE
                             ])

REGEX = re.compile(f"^{LOG_LINE_PATTERN}$")


def parse_line(line):
    """
    Convert a string log line into a dict
    :param line: Apache log line
    :rtype: dict|False
    """
    match = REGEX.search(line)
    if match:
        # The log line matched the regex, we get all the values matched
        remote_ip, log_name, user, time, request, response, size, referrer, user_agent = match.groups()

        # Create a dictionary from matched values
        entry = dict(
            remote_ip=remote_ip,
            log_name=log_name,
            user=user,
            time=time,
            request=request,
            response=parse_int(response),
            bytes=parse_int(size),
            referrer=referrer,
            user_agent=user_agent,
        )

        # Add extra entries to the dictionary by extracting data from log line
        entry.update(extract_method_and_url(request))
        entry.update(extract_client_information(user_agent))

        return entry
    # The regex didn't match
    logger.error(f'Could not understand line "{line}"')
    return False


def parse_int(value):
    """
    Log values are returned in string and empty fields are replaced with an hyphen.
    We want to be sure to have an integer as an output
    :param value: Integer as a string or "-"
    :rtype: int
    """
    if value == '-':
        value = 0
    return int(value)


def parse_log_file(file_name):
    """
    Open a file and create a list of dictionaries with each line as a dict
    :param file_name: File name as a string
    :rtype: [dict]
    """
    data = []
    with open(file_name, 'r') as fh:
        for line in fh:
            line_data = parse_line(line.strip())
            if line_data:
                data.append(line_data)
    logger.info(f"Read {len(data)} lines from file {file_name}")
    return data


DESKTOP_UA_RE = re.compile(
    r'.*(Windows NT \d+\.?\d*|Mac OS [A-z0-9._ ]+|Linux \d+(\.\d+)*)',
    re.IGNORECASE)
MOBILE_UA_RE = re.compile(
    r'.*(iPhone OS \d+(_\d+)*|Android \d+(\.\d+)*|iPad)',
    re.IGNORECASE)


def extract_client_information(user_agent):
    """
    Extract data from the user_agent field
    :param user_agent:
    :type user_agent: str
    :return: return a dictionary of the information extracted
    :rtype: dict
    """
    os_string = 'Unknown'

    mobile_os_match = MOBILE_UA_RE.match(user_agent)
    if mobile_os_match:
        os_string = mobile_os_match.group(1)
    else:
        desktop_os_match = DESKTOP_UA_RE.match(user_agent)
        if desktop_os_match:
            os_string = desktop_os_match.group(1)
        else:
            logger.debug(f'OS could not be guessed for UA "{user_agent}"')

    return dict(
        system_agent=os_string,
    )


METHOD_REGEX = re.compile(r"^([A-Z]+) ([^ ]+) (.*)$")


def extract_method_and_url(request):
    """
    Extract data from the request field
    :param request: "request" field as found in the log
    :return: Dictionary with with keys: method, url, protocol
    :rtype: dict[str,str|None]
    """
    request_match = METHOD_REGEX.search(request)
    method = None
    url = None
    protocol = None
    if request_match:
        method, url, protocol = request_match.groups()
    return dict(
        method=method,
        url=url,
        protocol=protocol,
    )


def generate_json(apache_log_file_name, output_json_file_name):
    """
    Takes an Apache log file and created a JSON file from it
    """
    with open(output_json_file_name, 'w') as json_file:
        # Extract the data from the log as a list of dictionaries
        data = parse_log_file(apache_log_file_name)
        # Create a JSON file with the data.
        # indent option allows to pretty-print the JSON, otherwise it will be written as a single line
        json.dump(data, json_file, indent=4)
        print(f"Wrote {len(data)} entries to file {output_json_file_name}")


def main():
    """
    Entrypoint for processing command line arguments
    """

    # Use argparse to describe command line arguments
    parser = argparse.ArgumentParser(description="Tool to parse apache logs")

    parser.add_argument(dest='apache_log_file', type=argparse.FileType('r'),
                        help="Input apache log input_files")
    parser.add_argument('-o', '--output-json', type=argparse.FileType('w'),
                        default='log.json', help="Output path of the JSON file")

    # Parse the command line arguments
    # The args contains the values extract from command line
    # If the values passed as arguments are not compatible with the arguments we defined,
    # argparse will automatically show the help
    args = parser.parse_args()

    # Call the function to generate the JSON using the args from the command line
    generate_json(
        args.apache_log_file.name,
        args.output_json.name)


# If the file is executed, not imported
if __name__ == '__main__':
    main()
