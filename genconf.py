#!/usr/bin/env python3

import ipaddress
import os
import subprocess

wg_path = '/usr/bin/wg'

def wg_command(cmd, input=None):
	cmd_out = subprocess.check_output([wg_path, cmd], input=input)
	return str(cmd_out, 'utf-8').strip()

def gen_ula_network(local_assigned, global_id, subnet_id):
	prefix = 0xfc
	if local_assigned:
		prefix |= 1

	addr = bytes([prefix]) + global_id + subnet_id + bytes([0] * 8)
	v6_addr = f"{addr[0]:02x}{addr[1]:02x}:"
	v6_addr += f"{addr[2]:02x}{addr[3]:02x}:"
	v6_addr += f"{addr[4]:02x}{addr[5]:02x}:"
	v6_addr += f"{addr[6]:02x}{addr[7]:02x}:"
	v6_addr += f"{addr[8]:02x}{addr[9]:02x}:"
	v6_addr += f"{addr[10]:02x}{addr[11]:02x}:"
	v6_addr += f"{addr[12]:02x}{addr[13]:02x}:"
	v6_addr += f"{addr[14]:02x}{addr[15]:02x}"
	v6_addr += "/64"

	return ipaddress.ip_network(v6_addr)

privkey = wg_command('genkey')
pubkey = wg_command('pubkey', privkey.encode('utf-8'))
psk = wg_command('genpsk')

print('Private Key:')
print(privkey)
print()

print('Public Key:')
print(pubkey)
print()

print('Pre-Shared Key:')
print(psk)
print()

global_id = os.getrandom(5, flags=os.GRND_RANDOM)
subnet_id = bytes([0,0])
ipv6_network = gen_ula_network(True, global_id, subnet_id)
print('Local IPv6 Unicast Addresses Network:')
print(ipv6_network)