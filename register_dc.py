import subprocess
import ipaddress
from config_class import config

wg_conf = config.wg_conf
wg_server = wg_conf['wg_server']
wg_username = wg_conf['wg_username']
wg_password = wg_conf['wg_password']
wg_link = wg_conf['wg_link']
wg_subnet = wg_conf['wg_subnet']

ping_command = f"ping -c 1 {wg_server}"
ping_process = subprocess.run(ping_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
if ping_process.returncode != 0:
    # Generate private key
    genkey_command = "wg genkey"
    private_key = subprocess.check_output(genkey_command, shell=True).decode("utf-8").strip()

    # Save private key to file and set permissions
    save_private_key_command = f"echo {private_key} | sudo tee /etc/wireguard/private.key"
    chmod_command = "sudo chmod go= /etc/wireguard/private.key"
    subprocess.run(save_private_key_command, shell=True)
    subprocess.run(chmod_command, shell=True)

    # Generate public key from private key and save to file
    pubkey_command = f"sudo cat /etc/wireguard/private.key | wg pubkey"
    save_public_key_command = "sudo tee /etc/wireguard/public.key"
    subprocess.run(f"{pubkey_command} | {save_public_key_command}", shell=True)
    pub_key = subprocess.check_output(pubkey_command, shell=True).decode("utf-8").strip()

    # Run the command to get a list of used IP addresses
    command = f"sshpass -p {wg_password} ssh -o StrictHostKeyChecking=no {wg_username}@{wg_link}  wg show wg0 allowed-ips | grep -E -o '([0-9]{{1,3}}[\.]){{3}}[0-9]{{1,3}}'"
    output = subprocess.check_output(command, shell=True).decode("utf-8")

    # Extract the used IP addresses from the output
    used_ips = set()
    for line in output.splitlines():
        ip_str = line.strip().split()[0]
        used_ips.add(ip_str)

    # Iterate through the range of IP addresses in the subnet
    subnet = ipaddress.ip_network(f'{wg_subnet}')
    for ip in subnet.hosts():
        if str(ip) not in used_ips:
            available_ip = ip
            break

    # Print the IP address and private key
    print(f"Using Wireguard IP address: {available_ip}")
    # Run the command
    subprocess.run(command, shell=True)
    sed_command = f"sudo sed -i 's/10.80.0.X/{available_ip}/' /etc/wireguard/wg0.conf"
    subprocess.run(sed_command, shell=True)
    set_peer_command = f"sshpass -p {wg_password} ssh -o StrictHostKeyChecking=no {wg_username}@{wg_link} sudo wg set wg0 peer {pub_key} allowed-ips {available_ip} persistent-keepalive 25"
    subprocess.run(set_peer_command, shell=True)
    enable_wg_command = f"sudo systemctl enable wg-quick@wg0.service"
    subprocess.run(enable_wg_command, shell=True)
    start_wg_command = f"sudo systemctl start wg-quick@wg0.service"
    subprocess.run(start_wg_command, shell=True)
else:
    # 10.75.0.1 is reachable, print error message
    print("WireGuard Setup is already Up")
