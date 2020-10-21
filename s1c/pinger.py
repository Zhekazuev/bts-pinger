# -*- coding: utf-8 -*-
"""
Checking BS on S1C interfaces
"""
from config import StarOS
import paramiko
import pandas
import time
import re


user = StarOS.STAROS_SCRIPTS_TACACS_USER
secret = StarOS.STAROS_SCRIPTS_TACACS_PASS
port = '22'
regex_enodeb_S1loopback = r'S1-loopback-1\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
regex_enodeb_S2loopback = r'S1-loopback-2\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
regex_mme = r'(\d{6})\:.*\s(\d{1,4}\.\d{1,4}\.\d{1,4}\.\d{1,4})'


def read_xlsx(path):
    codes = []
    data = pandas.read_excel(path)
    record = data.drop_duplicates(subset=["NodeId"], keep="first")
    xlsx_dict = record.to_dict(orient='records')
    for x in xlsx_dict:
        bts_code = str(x["NodeId"]).split('.')[0]
        match = re.search(r'\d{6}', bts_code)
        if match is not None:
            codes.append(match[0])
    return codes


def connect(host):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=host, port=port, username=user, password=secret)
    return ssh


def get_assoc(mmeassoc):
    mmeassoc.send('sho mme-service enodeb-association all' + '\n')
    time.sleep(10)
    output_enodebassoc = mmeassoc.recv(250000).decode('UTF-8')
    enode_b = re.findall(r"(\d{6})\:.*\s(\d{1,4}\.\d{1,4}\.\d{1,4}\.\d{1,4})",
                         output_enodebassoc)
    return enode_b


def get_loopbacks(mmeassoc):
    mmeassoc.send('context MME' + '\n')
    time.sleep(0.3)
    mmeassoc.send('sho ip int summary|grep S1' + '\n')
    time.sleep(0.3)
    ip_summary = mmeassoc.recv(1000)
    loopbacks = re.findall(r'\d+\.\d+\.\d+\.\d+', str(ip_summary))
    return loopbacks


def ping(mmeassoc, code, ip, loopback):
    mmeassoc.send(f'ping {ip} src {loopback} count 3\n')
    time.sleep(5)
    ping = mmeassoc.recv(1000).decode('UTF-8')
    ping = re.findall(r'\d+\s+packets.*time.*\d{4}ms', str(ping))
    return ping


def logprint(msg):
    directory = ''
    with open("pings.log", 'a') as f:
        f.write(msg)


def run_commands(host):
    try:
        # connection
        connection = connect(host)
        mmeassoc = connection.invoke_shell()

        # get a all associations and loopbacks on host
        all_assocs = get_assoc(mmeassoc)
        loopbacks = get_loopbacks(mmeassoc)
        for code in codes:
            for assoc in all_assocs:
                if code == assoc[0]:
                    #print(100*'=')
                    #print(host, code, assoc[1], loopbacks[0])
                    ping_loop_1 = ping(mmeassoc, code, assoc[1], loopbacks[1])
                    #print(ping_loop_1)
                    #print(75 * '+')
                    #print(host, code, assoc[1], loopbacks[1])
                    ping_loop_2 = ping(mmeassoc, code, assoc[1], loopbacks[1])
                    #print(ping_loop_2)
                    #print(100 * '=')
                    logprint(ping_loop_1)
                    logprint(ping_loop_2)
    finally:
        connection.close()


def main():
    path = "../ctp_17.xlsx"
    codes = read_xlsx(path)
    hosts = StarOS.mmehosts
    for region in hosts.keys():
        host = hosts.get(region).get("host")
        print(region, host)
        connection = connect(host)
        mmeassoc = connection.invoke_shell()

        allassocs = get_assoc(mmeassoc)
        loopbacks = get_loopbacks(mmeassoc)

        for code in codes:
            for assoc in allassocs:
                if code == assoc[0]:
                    stdin, stdout, stderr = connection.exec_command(f'ping {assoc[1]} src {loopbacks[1]} count 3\n')
                    data = stdout.read() + stderr.read()
                    print(data)
        connection.close()


if __name__ == '__main__':
    main()
