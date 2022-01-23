#!/usr/bin/env python3

import argparse
import ipaddress
import json
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

def main():
	parser = argparse.ArgumentParser(description='Process some integers.')
	parser.add_argument('command', type=str, help='generate|combine')
	parser.add_argument('self', type=str, nargs='?', help='self')
	parser.add_argument('peers', type=str, nargs='*',
                    	help='peers')
	parser.add_argument('--ipv4_network', type=str)
	parser.add_argument('--outfile', type=str)
	args = parser.parse_args()
	print(args)

	if args.command == 'generate':
		data = {
			'privkey': wg_command('genkey'),
			'psk': wg_command('genpsk')
		}
		data['pubkey'] = wg_command('pubkey', data['privkey'].encode('utf-8'))

		global_id = os.getrandom(5, flags=os.GRND_RANDOM)
		subnet_id = bytes([0,0])
		data["ipv4_network"] = args.ipv4_network if args.ipv4_network else None
		# data['ipv4_host'] = ipaddress.ip_interface(f"{next(data['ipv4_network'].hosts())}/24") 
		ipv6_network = gen_ula_network(True, global_id, subnet_id)
		ipv6_host = ipaddress.ip_interface(f"{next(ipv6_network.hosts())}/64")

		data['ipv6_network'] = str(ipv6_network)
		data['ipv6_host'] = str(ipv6_host)

		if args.outfile != None:
			with open(args.outfile, "w+") as output:
				json.dump(data, output, indent=4, sort_keys=True)
		else:
			print('Private Key:')
			print(data['privkey'])
			print()

			print('Public Key:')
			print(data['pubkey'])
			print()

			print('Pre-Shared Key:')
			print(data['psk'])
			print()

			print('Local IPv6 Unicast Addresses Network:')
			print(ipv6_network)
			print()

			print('Local IPv6 Unicast Host Address:')
			print(ipv6_host)

	if args.command == 'combine':
		assert args.self
		assert args.peers

		self_node = None
		peers = []

		with open(args.self, "r") as f:
			self_node = json.load(f)

		for peer in args.peers:
			with open(args.self, "r") as f:
				peers.append(json.load(f))

		print(self_node, peers)

		assert args.outfile

		with open(args.outfile, "w+") as f:
			f.write(f'[Interface]\n')
			f.write(f'PrivateKey = {self_node["privkey"]}\n')
			f.write(f'Address = {self_node["ipv6_host"]}\n')
			f.write(f'DNS = 1.1.1.1, 8.8.8.8\n')

			for peer in peers:
				f.write('\n')
				f.write(f'[Peer]\n')
				f.write(f'PublicKey = {peer["pubkey"]}\n')
				f.write(f'AllowedIPs = 0.0.0.0/0, ::0/0\n')
				f.write(f'PresharedKey = {self_node["psk"]}\n')
				f.write(f'PersistentKeepalive = 25\n')

if __name__ == '__main__':
	main()