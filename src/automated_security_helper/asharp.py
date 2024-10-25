#!/usr/bin/python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# asharp.py / Automated Security Helper - Aggregated Report Parser
# A tool to parse, ingest, and output ASH aggregated reports.

import datetime
import regex as re
import argparse
import json
from json import JSONEncoder
from automated_security_helper import __version__

# default filenames for input and output
DEF_INFILE='aggregated_results.txt'
DEF_OUTFILE='asharp_results.json'

# handle command line
cliparser = argparse.ArgumentParser( description="Automated Security Helper Aggregated Report Parser")
cliparser.add_argument('-i', '--input', help=f"File contained ASH aggregated results ({DEF_INFILE})")
cliparser.add_argument('-o', '--output', help="File to write ARP resulting model")
#cliparser.add_argument('-j', '--jq', help="Parse raw file and filter with jq")
cliparser.add_argument('-R', '--retain', action='store_true', help="TEMPORARY - Do not modify raw data output")
cliparser.add_argument('-s', '--stdout', action='store_true', help="Output ARP resulting model to console")
cliparser.add_argument('-v', '--verbose', action='store_true', help="Output instrumentation log")
cliparser.add_argument('--version', action='store_true', help="Output ASHARP version")
args = cliparser.parse_args()

# simply output version and exit
if args.version:
    print(__version__)
    exit(0)

# data parsing/collection from ASH aggregated report
aggregated = {}

# resulting data model
asharpmodel = {}

###
## Support functions
#

# basic debug log (this could be added to the model as asharp metadata)
debug_log = []

# basic instrumentation
def debug(x, y = 0):
    def debugout(s):
        print(s)
        debug_log.append(s)
    if args.verbose or y == 255:
        debugout(x)
    if y == 0: return
    debugout("!! access the help menu with -h or --help")
    exit(255)

# json encoder for datetime object
class DateTimeEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime.date, datetime.datetime)):
            return obj.isoformat()

###
## Parsing and extraction functions
#

# extract embedded JSON from output
def ExtractJsonFromData(data):

    # does minimal necessary to validate JSON
    # uses backref (should reduce regex greediness)
    result = re.findall(r"""(?xmsi)
        ^[\n\s\t]*
        (?P<json>
            (?>
                \{(?:[^{}"]|"(?:\\.|[^"\\])*"|(?&json))*\}  # objects
                |                                           # and/or
                \[(?:[^[\]]|"(?:\\.|[^"\\])*"|(?&json))*\]  # arrays
            )
        )
    """, data)

    #debug(json.dumps(result, cls=DateTimeEncoder, indent=4))
    return result

# extract ASH invoked provider sections
def ExtractSectionsFromData(data):

    # find all section boundaries and retrieve innards
    # uses a backref (should reduce regex greediness)
    result = re.findall(r'''(?xmsi)
        #############################################\n
        Start\s+of\s+([^\n]+)\n                                     # start marker
        #############################################\n
        (.*?)                                                       # provider output blob
        #############################################\n
        End\s+of\s+(\1)\n                                           # end marker
        #############################################
    ''', data)

    #debug(json.dumps(result, cls=DateTimeEncoder, indent=4))
    return result

# separate Grype, Syft, and Semgrep findings
def ExtractSecondarySections(data):

    # find all section boundaries and retrieve innards
    # uses a backref (should reduce regex greediness)
    #
    # ^^^ this is to ensure we don't encapsulate some undesirable
    # section and hence, miss reporting something.  This means
    # that all section start/end markers are IDENTICAL

    result = re.findall(r'''(?xmsi)
        >>>>>>\s+Begin\s+(\S+)\s+.+?\s+for\s+(.+?)\s+>>>>>>\n    # start marker
        (.*?)                                                    # provider output
        <<<<<<\s+End\s+(\1)\s+.+?\s+for\s+(\2)\s+<<<<<<          # end marker
    ''', data)

    #debug(json.dumps(result, cls=DateTimeEncoder, indent=4))
    return result

# need to parse cdk provider here and addModel accordingly
def parseCdkProvider(data):

    # rx for Warnings and Errors
    results = re.findall(r'''(?xmsi)

        # total pita - this will not extract the 2nd pattern, even if swapped
        # works well enough for now.  will revisit later.

        ^[\n]*   # just in case..
        (
        \[(Warning|Error)\s+at\s+([^\]]+)\]\s+
            (
                ([^:]+):\s+.+?                  # error refernce id
                |
                [^:]+:\s+'(Aws.+?)'\s+.+?       # warning reference id
            )
        [\n]+
        )
    ''', data)

    cdks = []
    for result in results:
        o = {
                'raw': result[0],
                'severity': result[1],
                'ref': result[2],
                'id': result[4],
                'result': result[3]
        }

        #debug(json.dumps(o, cls=DateTimeEncoder, indent=4))
        cdks.append(json.dumps(o, cls=DateTimeEncoder, indent=0))

    if not len(cdks):
        return

    return cdks

# parse out ASH report sections
def ParseAshSections(aggfile):

    # find, separate, and extract each providers output section
    sections = ExtractSectionsFromData(aggfile)

    # does data contain valid sections?
    if not sections:
        debug('!! Unable to find any section identifiers.')
        debug('!! Is this an ASH aggregate_results.txt file?', 255)

    # iterate through each section
    for section in sections:

        # sanity check - make sure the regex wasn't overly greedy
        if section[0] != section[2]:
            debug('!! Start and end do not match!!', 255)

        # identify the provider from the report filename
        prx = re.search(r'(grype|yaml|py|cdk|git|js)_report', section[0])
        if not prx:
            debug(f'!! No provider identified for {section[0]}', 255)
        provider = prx.group(1)

        # remove ansi, unprintables, and unicode from provider outout (just data section)
        # might be better to escape these.. thoughts?
        dsanitize = section[1].replace(r'\x1B(?:[@-Z\\]|\[[0-?]*[ -/]*[@-~])', '')
        dsanitize = dsanitize.replace(r'[^\x00-\x7F]+', '')
        ##dsanitize = dsanitize.replace(r'\u[a-fA-F0-9]{4}', '')
        ##dsanitize = dsanitize.replace(r'[\u0000-\uffff]', '')
        ##dsanitize = dsanitize.replace(r'\p{Mn}+', '')
        dsanitize = dsanitize.encode('ascii', 'ignore').decode()

        # collect the parsed information
        aggregated[provider] = {
            'file': section[0],
            'provider': provider,
            ##'output': section[1],  # unnecessary - removal occurs below
            'data': dsanitize if dsanitize else section[1]
        }

        # creates a model object representing the subsection output
        models = []
        def addModels(tool, file, arr):
            for a in arr:
                models.append({ 'tool': tool, 'file': file, 'data': a })
            return

        # need to separate findings found in different subsections
        # and cdk and git and js and py and yaml
        subsections = ExtractSecondarySections(section[1])
        for subsection in subsections:
            gmodel = None

            # if this is cdk provider, then we need to manually extract & generate json
            if provider in ['cdk']:
                gmodel = parseCdkProvider(subsection[2])
            else:
                gmodel = ExtractJsonFromData(subsection[2])

            # continue to next if no model data found
            if not gmodel:
                debug(f'-- {subsection[0]} model is {len(subsection[2])} and did not detect json')
                continue

            # add the extracted data to the models array for further processing
            addModels(subsection[0], subsection[1], gmodel)

        # process the extracted json object data (needs to be parsed/loaded)
        arr = []
        for m in models:
            data = m['data']
            tool = m['tool']
            file = m['file']

            # attempt to validate the extraction
            try:
                o = json.loads(data)
                arr.append({'tool': tool, 'file': file, 'data': o})

                # COMMENT THE FOLLOWING OUT TO RETAIN UNALTERED RAW OUTPUT
                #
                # - remove json artifacts from the provider data as we parse them
                # - what remains is what we did not parse.
                # - this doesn't remove manual extractions (eg. cdk)
                # - this was initially intended for debugging
                #   ..can be disabled if undesirable
                # - the "output" object (1 page up) was to capture raw output
                #   ..but maybe we prefer one over the other
                #
                aggregated[provider]['data'] = aggregated[provider]['data'].replace(data, '')

            except Exception as e:
                debug(f'!! error - {e} {m}')
                pass    # hmmm, continue?

            debug(f'-- {tool} model starts with "{data[0]}", contains {len(data)} bytes, and ends with "{data[:-5]}"')

        # place the extacted json objects into the provider data model
        if arr: aggregated[provider]['model'] = arr

        #debug(json.dumps(aggregated[provider]['model'], cls=DateTimeEncoder, indent=4))

    return aggregated

## Begin execution
#

def main():
    # read the ASH aggregated report as text blob
    if not args.input:
        debug("!! provide the path to the ASH aggregate report", 255)
    with open(args.input, 'r') as file:
        aggfile = file.read()

    # parse ASH report sections
    ParseAshSections(aggfile)

    # if output file specified then write to file
    if args.output:
        with open(args.output, 'w') as file:
            file.write(json.dumps(aggregated, cls=DateTimeEncoder, indent=4))

    # output it to screen
    if not args.output or args.stdout:
        print(json.dumps(aggregated, cls=DateTimeEncoder, indent=4))

if __name__ == "__main__":
    main()

# EOF
