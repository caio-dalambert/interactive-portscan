import socket
import sys
from urllib import request, error
from http.client import responses
import ssl
import threading
from queue import Queue
from termcolor import colored
from scapy.all import IP, UDP, sr1

main_ports = [20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 119, 143, 161, 162, 194, 443, 465, 514, 587, 631, 993, 995, 3000, 3306, 5432, 6379, 8000, 8080, 8443, 8888, 27017, 5000, 5001, 6000, 6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889]

unverified_ssl_context = ssl._create_unverified_context()

def print_ports(open_ports):
	print ("\n" + colored("=" * 50, "magenta", "on_magenta") + "\n")
	print (colored("Open ports found: ", "magenta", attrs=['bold']) + "\n")
	for port, service in open_ports.items():
		print (colored(f"- Port","green", attrs=['bold']), colored(f"{port}","yellow", attrs=['bold']) + colored(":", "green", attrs=['bold']), colored(f"{service}", "green"))

def save_log(host, open_ports):

	with open(f"log_{host}.txt","w") as file:
		file.write(f"Scanning log of {host}\n")
		file.write("=" * 50 + "\n")
		for port, service in open_ports.items():
			file.write(f"- Port {port}: {service}\n")
	print (colored(f"\n- Log saved as log_{host}.txt", "yellow", attrs=["underline"]))

def get_http_banner(host,port):

	try:
		if port == 443:
			url = f"https://{host}:{port}/"
		else:
			url = f"http://{host}:{port}/"

		response = request.urlopen(url, timeout=2, context=unverified_ssl_context)
		headers = response.info()

		status_code = response.getcode()
		status_message = responses.get(status_code, colored("Unknown status.", "red", attrs=['underline']))

		server = headers.get('Server')
		content_type = headers.get('Content-Type')

		if server:
			server_info = server
		else:
			server_info = colored("'Server' field not found.", "red", attrs=['underline'])

		if content_type:
			content_type_info = content_type
		else:
			content_type_info = colored("'Content-Type' field not found.", "red", attrs=['underline'])

		return f"{status_code} - {status_message} - {server_info} - {content_type_info}"

	except error.HTTPError as e:
		status_message = responses.get(e.code, "Unknown status.")
		return colored(f"HTTP Error {e.code} - {status_message}.", "red", attrs=['blink', 'bold'])

	except error.URLError as e:
		return colored(f"URL Error - {e.reason}.", "red", attrs=['blink', 'bold'])

	except Exception as e:
		return colored(f"Unknown Error - {str(e)}.", "red", attrs=['blink', 'bold'])

def udp_port_scanning(host, port, open_ports):

	try:
		packet = IP(dst=host)/UDP(dport=port)
		udp_response = sr1(packet, timeout=1, verbose=0)

		if udp_response is None:
			return
		elif udp_response.haslayer(UDP):
			open_ports[port]="Open UDP port."
		elif udp_response.haslayer(ICMP):
			return
	except Exception as e:
		return

def tcp_port_scanning(host, port, open_ports):

	mysocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	mysocket.settimeout(0.5)


	code = mysocket.connect_ex((host, port))


	if code == 0:
		banner = colored("Service not identified.", "red", attrs=['bold'])
		if port in [80, 443, 8080, 8443, 8000, 8888, 5000, 3000]:
			banner = get_http_banner(host, port)
		else:
			try:
				banner = mysocket.recv(1024).decode().replace("\n", "").strip()
			except:
				pass
		open_ports[port] = banner
	mysocket.close()


def worker(queue, host, open_ports):

	while not queue.empty():
		port = queue.get()
		tcp_port_scanning(host, port, open_ports)
		queue.task_done()


def scan_with_threading(host, ports):

	open_ports = {}
	queue = Queue()

	for port in ports:
		queue.put(port)

	for _ in range(10):
		thread = threading.Thread(target=worker, args=(queue, host, open_ports))
		thread.daemon = True
		thread.start()
	queue.join()
	return open_ports


def port_scan(host, ports, protocol="tcp"):

	open_ports = {}


	if protocol == "tcp":
		open_ports = scan_with_threading(host, ports)

	elif protocol == "udp":
		for port in ports:
			if udp_port_scanning(host, port, open_ports):
				open_ports[port] = colored("Open UDP port.", "green", attrs=['bold'])


	return open_ports

def validate_protocol():
	while True:
		protocol = input(colored("> ", "green", attrs=['bold'])).lower()
		if protocol in ["tcp", "udp"]:
			return protocol
		else:
			print(colored("Invalid protocol. Please type TCP or UDP.", "red", attrs=['bold']))

def display_menu():

	while True:
		print ("\n" + colored("=" * 50, "magenta", "on_magenta") + "\n")
		print (colored("Select a scanning option:", "magenta", attrs=['bold']),"\n")
		print (colored("1.", "magenta", attrs=['bold']), "Scan only the main ports.")
		print (colored("2.", "magenta", attrs=['bold']), "Scan ALL ports (1-65535). [WARNING: This may take a while!]")
		print (colored("3.","magenta", attrs=['bold']), "Type the ports you want to scan.")
		print (colored("4.","magenta", attrs=['bold']), "Type a range of ports to scan (ex: 20-80).\n")

		print ("Type the number of the desired option:")


		option = input(colored("> ", "green", attrs=['bold']))

		if option == "1":
			print ("\nChoose the transport protocol (tcp/udp): ")
			protocol = validate_protocol()
			return main_ports, protocol

		elif option == "2":
			print (colored("\nWarning: Scanning all the ports may take a while.", "red", attrs=['underline']))
			print ("Proceed with the scan? (y/n):")

			confirm = input(colored("> ", "green", attrs=['bold']))

			if confirm.lower() == 'y':
				print ("\nChoose the transport protocol (tcp/udp): ")
				protocol = validate_protocol()
				return list(range(1, 65536)), protocol
			elif confirm.lower() == 'n':
				print (colored("\nScanning cancelled. Going back to the menu.", "red", attrs=['bold']))
			else:
				print (colored("\nInvalid answer. Going back to the menu.", "red", attrs=['bold']))

		elif option == "3":
			print ("\nType the ports that you want to scan, separated by commas:")
			ports = input(colored("> ", "green", attrs=['bold']))
			ports = [int(p) for p in ports.split(',')]
			if len(ports) > 100:
				print (colored("\nWarning: Scanning a lot of ports may take a while.", "red", attrs=['bold']))
				print ("Proceed with the scan? (y/n):")
				manual_confirm = input(colored("> ", "green", attrs=['bold']))

				if manual_confirm.lower() == 'y':
					print ("\nChoose the transport protocol (tcp/udp): ")
					protocol = validate_protocol()
					return ports, protocol
				elif manual_confirm.lower() == 'n':
					print (colored("\nScanning cancelled. Going back to the menu.", "red", attrs=['bold']))
				else:
					print (colored("\nInvalid answer. Going back to the menu.", "red", attrs=['bold']))

			else:
				print ("\nChoose the transport protocol (tcp/udp): ")
				protocol = validate_protocol()
				return ports, protocol

		elif option == "4":
			print ("\nType the range of ports (ex: 20-80):")
			port_range = input(colored("> ", "green", attrs=['bold']))
			start, end = port_range.split("-")
			ports = list(range(int(start), int(end) + 1))

			if len(ports) > 100:
				print (colored("\nWarning: Scanning a lot of ports may take a while.", "red", attrs=['underline']))
				print ("Proceed with the scan? (y/n):")
				range_confirm = input(colored("> ", "green", attrs=['bold']))
				if range_confirm.lower() == 'y':
					print ("\nChoose the transport protocol (tcp/udp):")
					protocol = validate_protocol()
					return ports, protocol
				elif range_confirm.lower() == 'n':
					print (colored("\nScanning cancelled. Going back to the menu.", "red", attrs=['bold']))
				else:
					print (colored("\nInvalid answer. Going back to the menu.", "red", attrs=['bold']))

			else:
				print ("\nChoose the transport protocol (tcp/udp):")
				protocol = validate_protocol()
				return ports, protocol

		else:
			print (colored("\nInvalid option. Going back to the menu.", "red", attrs=['bold']))

def dns_resolver(host):

	try:
		ip = socket.gethostbyname(host)
		print (colored(f"\nResolved host: {host} -> {ip}", "green", attrs=['underline']))
		print ("Continue the scan with this IP? (y/n): ")
		confirm = input(colored("> ", "green", attrs=['bold']))

		if confirm.lower() == 'y':
			return ip
		elif confirm.lower() == 'n':
			print (colored("\nProceeding with the scan using the original domain.","white", attrs=['underline']))
			return host
		else:
			print (colored("\nInvalid answer. Proceeding using the original domain.\n", "red", attrs=['bold']))
			return host

	except socket.gaierror:
		sys.exit(colored("Couldn't resolve the host.", "red", attrs=['underline']) + "\n")


def ask_to_save_log_file(host, open_ports):

	print ("\n" + colored("=" * 50, "yellow", "on_yellow") + "\n")
	print (colored("Would you like to create a log file? (y/n): ", "yellow", attrs=['underline']))
	confirm = input(colored("> ", "green", attrs=['bold'])).lower()
	if confirm == 'y':
		save_log(host, open_ports)
	elif confirm == 'n':
		print ("\n" + colored("No scanning log file was created.", "yellow", attrs=['underline']))
	else:
		print ("\n" + colored("Invalid answer. No scanning log file will be created.", "yellow", attrs=['bold']))

if __name__ == "__main__":
	if len(sys.argv) != 2:
		print ("\n" + colored("Correct formatting: python3 portscan.py <host>", "red", attrs=['underline']) + "\n")
		sys.exit()

	host = sys.argv[1]

	print ("\n" + colored("=" * 50, "green", "on_green"))

	try:
		socket.inet_aton(host)
		print (f"\nThe provided host is an IP: {host}")
	except socket.error:
		print (f"\nThe provided host is a domain. Do you want to resolve the IP of {host}? (y/n): ")
		resolve = input(colored("> ", "green", attrs=['bold']))

		if resolve.lower() == 'y':
			host = dns_resolver(host)
		elif resolve.lower() == 'n':
			print ("\nProceeding with the scan using the original domain.")
		else:
			print (colored("\nInvalid answer. Proceeding using the original domain.", "red", attrs=['underline']))

	chosen_ports, protocol = display_menu()
	open_ports = port_scan(host, chosen_ports, protocol)
	print_ports(open_ports)
	ask_to_save_log_file(host, open_ports)

	print ("\n" + colored("=" * 50, "green", "on_green") + "\n")
	print (colored("Scan complete.\n", "green", attrs=['bold']))
	print (colored("=" * 50, "green", "on_green") + "\n")
