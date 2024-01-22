import getpass
import psutil
import netifaces as ni
import subprocess
import re
import ipaddress

#------------------------Show Interfaces-----------------------------------------
def get_network_physical_address(netInterfaceName):
    nics = psutil.net_if_addrs()
    macAddress = ([j.address for i in nics for j in nics[i] if i==netInterfaceName and j.family==psutil.AF_LINK])[0]
    return macAddress.replace('-',':')

def show_interfaces():
    net_stats = psutil.net_if_stats()

    # Print table header
    print("{:<15} {:<15} {:<12} {:<20} {:<15}".format("Intf", "Ip address", "Flags", "MAC", "MTU"))

    for iface, stats in net_stats.items():
        # Check if the interface has an IPv4 address
        if ni.AF_INET in ni.ifaddresses(iface):
            ip = ni.ifaddresses(iface)[ni.AF_INET][0]['addr']
        else:
            ip = "N/A"

        # Check if 'up' flag is present
        flags = "UP" if stats.isup else "DOWN"

        print("{:<15} {:<15} {:<12} {:<20} {:<15}".format(iface, ip, flags, get_network_physical_address(iface), stats.mtu))
        
#------------------------------Show routes---------------------------------------------
def parse_ip_routes(output):
    routes = []

    # Split the output into lines and process each line
    for line in output.split('\n'):
        if line.strip():
            # Use regular expressions to extract relevant information
            match_default = re.match(r'default(?: via (?P<gateway>[\d\.]+))? dev (?P<interface>\S+)(?: proto \S+)?(?: src (?P<source>[\d\.]+))?', line)
            match_network = re.match(r'(?P<route>[\d\.]+(?:/\d+)?) dev (?P<interface>\S+)(?: proto \S+)?(?: scope \S+)?(?: src (?P<source>[\d\.]+))?', line)

            if match_default:
                route_info = {
                    'route': 'default',
                    'gateway': match_default.group('gateway') or None,
                    'interface': match_default.group('interface'),
                    'source': match_default.group('source') or None
                }
                routes.append(route_info)
            elif match_network:
                route_info = {
                    'route': match_network.group('route'),
                    'interface': match_network.group('interface'),
                    'source': match_network.group('source') or None
                }
                routes.append(route_info)
            else:
                # Print the raw output for lines that don't match the expected formats
                print(f"Unrecognized line: {line}")

    return routes

def show_ip_routes():
    try:
        # Run the 'ip route show' command and capture the output
        result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True, check=True)

        # Parse the output to extract route information
        routes = parse_ip_routes(result.stdout)

        # Print the table header
        print("{:<20} {:<20} {:<20} {:<20}".format("Route", "Gateway", "Interface", "Source"))

        # Print the parsed information in a table-like format
        for route in routes:
            gateway_value = route.get('gateway', 'N/A') or 'N/A'
            source_value = route.get('source', 'N/A') or 'N/A'
            print("{:<20} {:<20} {:<20} {:<20}".format(route['route'], gateway_value, route['interface'], source_value))
    
    except subprocess.CalledProcessError as e:
        # Handle any errors that occurred during command execution
        print(f"Error: {e}")
        print(f"Command output (stderr): {e.stderr}")

#-----------------------------Create bridge---------------------------------------
def create_bridge(bridge_name):
    try:
        # Check if the bridge already exists
        result = subprocess.run(["sudo", "brctl", "show", bridge_name], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"Bridge {bridge_name} already exists; can't create bridge with the same name")
        else:
            # Bridge does not exist, proceed with creation
            subprocess.run(["sudo", "brctl", "addbr", bridge_name])
            print(f"Bridge {bridge_name} created successfully!")

            # Bring up the bridge interface
            subprocess.run(["sudo", "ip", "link", "set", "dev", bridge_name, "up"])
            print(f"Bridge {bridge_name} is now up!")

    except Exception as e:
        print(f"Error creating/bringing up bridge {bridge_name}: {e}")

#-----------------------------Configure IP----------------------------------------
def configure_interface_ip(interface_name, ip_subnet):
    try:
        # Parse the input IP address and subnet
        ip_network = ipaddress.IPv4Network(ip_subnet, strict=False)

        # Run the ip address add command to configure the IP address and subnet mask
        subprocess.run(["sudo", "ip", "address", "add", f"{ip_network.network_address}/{ip_network.netmask}", "dev", interface_name])
        print(f"IP address {ip_network.network_address}/{ip_network.netmask} configured on {interface_name} successfully!")
    except Exception as e:
        print(f"Error configuring IP address on {interface_name}: {e}")

#--------------------------------------Login---------------------------------------
def login():
    correct_username = "admin"
    correct_password = "admin"

    username = input("login: ")
    password = getpass.getpass("password: ")

    if username == correct_username and password == correct_password:
        print("### Welcome to config linux network system ###")
        return True
    elif username != correct_username:
        print("Login failed. Incorrect login.")
        return False
    else:
        print("Login failed. Incorrect password.")
        return False

#----------------------Main-------------------------------------
if __name__ == "__main__":
    exit = True
    while exit:
        loginB = login()
        if loginB:
            while True:
                command = input("> ")

                if command == "exit":
                    print("Closing the config system.")
                    exit = False
                    break
                elif command == "show interfaces":
                    show_interfaces()
                elif command == "show routes":
                    show_ip_routes()
                elif command.startswith("show"):
                    print("Invalid command format. Please use 'show interfaces' or 'show routes'")
                elif command.startswith("configure"):
                    # Using regex to extract interface name and IP address/subnet mask
                    match = re.match(r"^configure\s+(\S+)\s+ip\s+(\S+)$", command)
                    if match:
                        interface_name = match.group(1)
                        ip_subnet = match.group(2)
                        configure_interface_ip(interface_name, ip_subnet)
                    else:
                        print("Invalid input format. Please use: configure <interface_name> ip <ip-address/subnet mask>")
                elif command.startswith("create"):
                    parts = command.split()
                    if len(parts) == 3 and parts[0] == "create" and parts[1] == "bridge":
                        bridge_name = parts[2]
                        create_bridge(bridge_name)
                    else:
                        print("Invalid input format. Please use 'create bridge <bridge_name>'.")
                else:
                    print("Invalid command.")