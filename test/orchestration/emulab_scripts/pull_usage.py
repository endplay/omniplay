#!/usr/bin/python


import requests
import json
import time
import datetime

requests.packages.urllib3.disable_warnings()

TYPE_LIST = "children"
NAME = "name"
USED = "howfull"
TOTAL = "size"

def get_data(print_total):

    with open("d710.out", "a") as d710file, open("r320.out","a") as r320file:
        r = requests.get("https://www.cloudlab.us/cloudlab-fedonly.json", verify=False)
        j = r.json()
        for obj in j[TYPE_LIST]:
            for pc_type in obj[TYPE_LIST]:
                if pc_type[NAME] == "d710":
                    d710file.write("," + str(pc_type[USED]))            
                    if print_total:
                        print pc_type[NAME], pc_type[TOTAL]

                if pc_type[NAME] == "r320":
                    r320file.write("," + str(pc_type[USED]))
                    if print_total:
                        print pc_type[NAME], pc_type[TOTAL]


def main():

    print datetime.datetime.now().time()

    get_data(True)
    while True:
        get_data(False)
        time.sleep(5)


main()
