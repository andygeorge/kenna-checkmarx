#!/usr/bin/env python

import sys, requests, json
from bs4 import BeautifulSoup

api_endpoint_assets = "https://api.kennasecurity.com/assets"
api_endpoint_vulns = "https://api.kennasecurity.com/vulnerabilities"
token = "123abc"
headers = {'content-type': 'application/json', 'X-Risk-Token': token}

cwe_wasc_dict = {
    "79": "8",
    "77": "19",
    "552": "16",
    "113": "25",
    "248": "13",
    "209": "13"
}

file = sys.argv[1]
handler = open(file).read()
soup = BeautifulSoup(handler)

# Input (xml):
#<Query>
#    <Result>
#        <Path>
#            <PathNode>
#                <Line>
#                <Column>
#                <Snippet>
#                    <Line>
#                        <Number>
#                        <Code>

# Output (json):
# {
#   "vulnerability": {
#     "wasc_id": the_wasc_id,
#     "primary_locator": "file",
#     "file": the_filename
#   }
# }

# each vuln
for query in soup.find_all('query'):
    # get cwe/wasc
    the_cwe_id = query['cweid']
    the_wasc_id = cwe_wasc_dict[the_cwe_id]
    
    # iterate through results
    for result in query.find_all('result'):
        the_filename = str(result['filename'])

        vuln_json = {"vulnerability":{"wasc_id" : "WASC-" + the_wasc_id,"primary_locator" : "file","file" : the_filename}}
        print(vuln_json)

        # POST new vuln/asset
        response = requests.post(api_endpoint_vulns, data=json.dumps(vuln_json), headers=headers)
        print(response)

        # iterate through path objects and build code snippets
        #for path in result.find_all('path'):
            #print(path['resultid'])
            #for pathnode in path.find_all('pathnode'):
                #print(pathnode.filename)

