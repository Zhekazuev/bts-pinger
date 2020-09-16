"""
Checking BS on S1U interfaces
"""
from threading import Thread
from config import StarOS
from config import Netbox
import paramiko
import requests
import json
import time
import re


user = StarOS.STAROS_SCRIPTS_TACACS_USER
secret = StarOS.STAROS_SCRIPTS_TACACS_PASS
nb_url = Netbox.nb_url
headers = Netbox.headers


class SSH:
    """
    Class SSH is needed for a simple connection, execute command and put/get files
    """
    def __init__(self, host, user, password, port=22):
        self.client = None
        self.conn = None
        self.host = host
        self.user = user
        self.password = password
        self.port = port

    def connect(self):
        """
        Create ssh connection
        """
        if self.conn is None:
            try:
                self.client = paramiko.SSHClient()
                self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.client.connect(hostname=self.host, port=self.port, username=self.user, password=self.password)
                return self.client
            except paramiko.AuthenticationException as authException:
                print(f"{authException}, please verify your credentials")
            except paramiko.SSHException as sshException:
                print(f"Could not establish SSH connection: {sshException}")

    def execute_commands(self, cmd):
        """
        Execute command in succession.

        :param cmd: One command for example: show administrators
        :type cmd: str
        """
        stdin, stdout, stderr = self.client.exec_command(cmd)
        stdout.channel.recv_exit_status()
        response = stdout.readlines()
        return response

    def put(self, localpath, remotepath):
        sftp = self.client.open_sftp()
        sftp.put(localpath, remotepath)
        time.sleep(10)
        sftp.close()
        self.client.close()

    def get(self, remotepath, localpath):
        sftp = self.client.open_sftp()
        sftp.get(remotepath, localpath)
        time.sleep(10)
        sftp.close()
        self.client.close()

    def disconnect(self):
        """Close ssh connection."""
        if self.client:
            self.client.close()


def get_all_enodeb_from_region(region):
    all_bts_url = f"{nb_url}/api/dcim/devices/?tenant={region}-region-mbh&role=lte&limit=0"
    all_bts = json.loads(requests.get(all_bts_url, headers=headers).text).get("results")
    return all_bts


def get_s1u_address_by_enodeb(lte_number):
    bts_url = f"{nb_url}/api/ipam/ip-addresses/?device={lte_number}&interface=LTE%20S1-U%20MTS"
    bts_s1u = json.loads(requests.get(bts_url, headers=headers).text).get("results")
    return bts_s1u


def get_s1c_address_by_enodeb(lte_number):
    bts_url = f"{nb_url}/api/ipam/ip-addresses/?device={lte_number}&interface=LTE%20S1-C%20MTS"
    bts_s1c = json.loads(requests.get(bts_url, headers=headers).text).get("results")
    return bts_s1c


def get_all_addresses_by_enodeb(lte_number):
    bts_url = f"{nb_url}/api/ipam/ip-addresses/?device={lte_number}"
    bts = json.loads(requests.get(bts_url, headers=headers).text).get("results")
    return bts


def get_spgw(shell):
    spgw_addressess = []
    shell.send('context SPGW' + '\n')
    shell.send('show configuration context SPGW' + '\n')
    time.sleep(7)
    configuration = shell.recv(250000).decode('UTF-8')
    configuration = configuration.split('gtpu-service S5U-PGW-SVC')
    addressess = re.findall(r'.*\s+(\d{1,4}\.\d{1,4}\.\d{1,4}\.\d{1,4})\s+bearer-type\s+all', configuration[0])
    for address in addressess:
        spgw_addressess.append(address)
    return spgw_addressess


def pinger(shell, ip, loopback):
    shell.send(f'ping ' + ip + ' src ' + loopback + ' count 2' + '\n')
    time.sleep(1)
    ping = shell.recv(1000).decode('UTF-8')
    return ping


def procedure(host, spgw_addresses, enodebes, file_path):
    try:
        # connection
        ssh = SSH(host=host, user=user, password=secret)
        shell = ssh.connect().invoke_shell()
        good_ping = []
        bad_ping = []
        time.sleep(1)
        shell.send('context SPGW' + '\n')
        time.sleep(1)

        for spgw in spgw_addresses:
            for enodeb in enodebes:
                ping_1 = pinger(shell, enodeb, spgw)
                if re.search(r'\d+\s+bytes\s+from\s+\d{1,4}\.\d{1,4}\.\d{1,4}\.\d{1,4}:', ping_1) is not None:
                    time.sleep(2)
                    good_ping.append(enodeb)
                else:
                    time.sleep(12)
                    bad_ping.append(enodeb)
                ping_2 = shell.recv(1000).decode('UTF-8')
                ping = ping_1 + ping_2
                file = open(file_path, "a")
                file.write(ping + "\n")
                file.write('='*100 + "\n")
                file.close()
                print(ping)

        file = open(file_path, "a")
        file.write("Number of good ping BTS = " + str(len(good_ping)) + "\n")
        file.close()
        good_bts_path = 'good_bts.txt'
        for bts in list(set(good_ping)):
            file = open(good_bts_path, "a")
            file.write(bts + "\n")
            file.close()
        file = open(file_path, "a")
        bad_bts_path = 'bad_bts.txt'
        file.write("Number of bad ping BTS = " + str(len(bad_ping)) + "\n")
        file.close()
        for bts in list(set(bad_ping)):
            file = open(bad_bts_path, "a")
            file.write(bts + "\n")
            file.close()
    finally:
        ssh.disconnect()


def main():
    ultrahosts = StarOS.ultrahosts
    host_1 = ultrahosts.get("brest")[0].get("host")
    host_2 = ultrahosts.get("brest")[1].get("host")
    print("Getting SPGW addresses from first node...")
    ssh = SSH(host=host_1, user=user, password=secret)
    shell = ssh.connect().invoke_shell()
    spgw_addresses_1 = get_spgw(shell)
    ssh.disconnect()
    print(spgw_addresses_1)
    print("Getting SPGW addresses from first node successfully")

    print("Getting SPGW addresses from second node...")
    ssh = SSH(host=host_2, user=user, password=secret)
    shell = ssh.connect().invoke_shell()
    spgw_addresses_2 = get_spgw(shell)
    ssh.disconnect()
    print(spgw_addresses_2)
    print("Getting SPGW addresses from second node successfully")

    print(f"Getting EnodeB's from Netbox...")
    enodebes = get_all_enodeb_from_region("brest")
    print(len(enodebes))
    print(f"Getting EnodeB's from Netbox successfully")

    enodebes_addresses = []
    print(f"Getting S1U addresses from Netbox...")
    for enodeb in enodebes:
        enodeb_s1u = get_s1u_address_by_enodeb(enodeb.get("name"))
        enodebes_addresses.append(enodeb_s1u[0].get("address").split("/")[0])
        print(enodeb_s1u[0].get("address").split("/")[0])
    print(f"Getting S1U addresses from Netbox successfully")

    log_path_1 = 'log_file_1.txt'
    log_path_2 = 'log_file_2.txt'

    thread1 = Thread(target=procedure, args=(host_1, spgw_addresses_1[0:2], enodebes_addresses, log_path_1))
    thread2 = Thread(target=procedure, args=(host_1, spgw_addresses_1[3:5], enodebes_addresses, log_path_1))
    thread3 = Thread(target=procedure, args=(host_1, spgw_addresses_1[6:8], enodebes_addresses, log_path_1))
    thread4 = Thread(target=procedure, args=(host_1, spgw_addresses_1[9:11], enodebes_addresses, log_path_1))
    thread5 = Thread(target=procedure, args=(host_2, spgw_addresses_2[0:2], enodebes_addresses, log_path_2))
    thread6 = Thread(target=procedure, args=(host_2, spgw_addresses_2[3:5], enodebes_addresses, log_path_2))
    thread7 = Thread(target=procedure, args=(host_2, spgw_addresses_2[6:8], enodebes_addresses, log_path_2))
    thread8 = Thread(target=procedure, args=(host_2, spgw_addresses_2[9:11], enodebes_addresses, log_path_2))

    thread1.start()
    thread2.start()
    thread3.start()
    thread4.start()
    thread5.start()
    thread6.start()
    thread7.start()
    thread8.start()
    thread1.join()
    thread2.join()
    thread3.join()
    thread4.join()
    thread5.join()
    thread6.join()
    thread7.join()
    thread8.join()


if __name__ == '__main__':
    main()
