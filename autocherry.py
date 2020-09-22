#!/usr/bin/env python3

from xml.etree import ElementTree as ET
from libnmap.parser import NmapParser
import os
import argparse

parser = argparse.ArgumentParser()
exgroup = parser.add_mutually_exclusive_group(required=True)
exgroup.add_argument('-d', action='store', dest='dir', help="AutoRecon target directory to parse")
exgroup.add_argument('-e', action='store_true', dest='empty', help="Do not parse an AutoRecon target directory and create an empty template")
parser.add_argument('-o', '--output', action='store', dest='output_file', default="autocherry", help="Name of output Cherrytree file. Defaults to 'autocherry.ctd'")
args = parser.parse_args()

# Nmap can return service names that don't match what AutoRecon names its output files.
# TODO: Just read these from service_scans_default.toml or a specified service_scans file
services_dict = {
    'apani1':'cassandra',
    'ipp':'cups',
    'domain':'dns',
    'netbios-ssn':'smb',
    'netbios-ns':'smb',
    'microsoft-ds':'smb',
    'ftp-data':'ftp',
    'kpasswd':'kerberos',
    'kpasswd5':'kerberos',
    'kerberos-sec':'kerberos',
    'mongod':'mongodb',
    'ms-sql':'mssql',
    'java-rmi':'rmi',
    'rmiregistry':'rmi',
    'msrpc':'rpc',
    'rcpbind':'rpc',
    'erpc':'rpc',
    'sip':'asterisk'
}

# Autorecon uses a '-' separator instead of '_' for some nmap service output files in service_scans_default.toml
# TODO: Make a PR to fix this because it's probably unintentional
dash_services = ['tftp', 'telnet','snmp']


def create_nmap_node(libnmap_service, scans_dir, parent_node, uid):
    service_string = get_service_string(libnmap_service)
    if libnmap_service.service in dash_services:
        service_scan_filename = os.path.abspath(os.path.join(scans_dir, libnmap_service.protocol.lower() + "_" + str(libnmap_service.port) + "_" + service_string.lower() +"-nmap"+".txt"))
    else:
        service_scan_filename = os.path.abspath(os.path.join(scans_dir, libnmap_service.protocol.lower() + "_" + str(libnmap_service.port) + "_" + service_string.lower() +"_nmap"+".txt"))
    try:
        with open(service_scan_filename) as f: 
            libnmap_service_scan = f.read()
        service_nmap_node = ET.SubElement(parent_node, "node", foreground="", is_bold="False", name="nmap", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
        ET.SubElement(service_nmap_node, "rich_text").text = libnmap_service_scan
        uid += 1
    except IOError as error:
        print(f"[!] Error attempting to create nmap subnode for service on port {libnmap_service.port} ({service_string}). AutoRecon may not generate a file for this service.\n{error}")
    return uid


def create_udp_service_node(libnmap_service, scans_dir, parent_node, uid):
    service_string = get_service_string(libnmap_service)
    service_node = ET.SubElement(parent_node, "node", custom_icon_id="34", foreground="", is_bold="False", name=str(libnmap_service.port) + " (" + libnmap_service.protocol.upper() + ") - " + service_string.upper(), prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1
    uid = create_nmap_node(libnmap_service, scans_dir, service_node, uid)
    if libnmap_service.service == "snmp":
        uid = create_snmp_node(libnmap_service, scans_dir, service_node, uid)
    return uid


def create_tcp_service_node(libnmap_service, scans_dir, parent_node, uid):
    service_string = get_service_string(libnmap_service)
    # Don't create nodes for open dynamic RPC ports
    if service_string == 'rpc' and libnmap_service.port >= 49152:
        return uid
    service_node = ET.SubElement(parent_node, "node", foreground="", is_bold="False", name=str(libnmap_service.port) + " (" + libnmap_service.protocol.upper() + ") - " + service_string.upper(), prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1
    uid = create_nmap_node(libnmap_service, scans_dir, service_node, uid)
    if service_string == "http":
        uid = create_http_subnodes(libnmap_service, scans_dir, service_node, uid)
    if service_string == "smb":
        uid = create_smb_subnodes(libnmap_service, scans_dir, service_node, uid)
    return uid


def create_snmp_node(libnmap_service, scans_dir, parent_node, uid):
    snmp_node = ET.SubElement(parent_node, "node", foreground="", is_bold="False", name="snmp", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1
    ET.SubElement(snmp_node, "rich_text").text = f"Run snmp-check and check the snmpwalk output files in {scans_dir}."
    onesixtyone_node = ET.SubElement(snmp_node, "node", foreground="", is_bold="False", name="onesixtyone", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1
    try:
        with open(os.path.abspath(os.path.join(scans_dir, f"udp_{str(libnmap_service.port)}_{libnmap_service.service}_onesixtyone.txt"))) as f: 
            onesixtyone_scan = f.read()
        ET.SubElement(onesixtyone_node, "rich_text").text = onesixtyone_scan
    except IOError as error:
        print(error)
    return uid


def create_smb_subnodes(libnmap_service, scans_dir, parent_node, uid):
    smbclient_node = ET.SubElement(parent_node, "node", foreground="", is_bold="False", name="smbclient", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1
    try:
        with open(os.path.abspath(os.path.join(scans_dir, "smbclient.txt"))) as f: 
            smbclient_scan = f.read()
        ET.SubElement(smbclient_node, "rich_text").text = smbclient_scan
    except IOError as error:
        print(error)
    smbmap_share_node = ET.SubElement(parent_node, "node", foreground="", is_bold="False", name="smbmap", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1
    try:
        with open(os.path.abspath(os.path.join(scans_dir, "smbmap-share-permissions.txt"))) as f: 
            smbmap_share_scan = f.read()
        ET.SubElement(smbmap_share_node, "rich_text").text = smbmap_share_scan
    except IOError as error:
        print(error)
    return uid


def create_http_subnodes(libnmap_service, scans_dir, parent_node, uid):
    gobuster_node = ET.SubElement(parent_node, "node", foreground="", is_bold="False", name="gobuster", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1
    # libnmap.objects.service doesn't discern between http and https, so we need to use port number
    if libnmap_service.port == 443:
        gobuster_filename = f"tcp_{str(libnmap_service.port)}_https_gobuster.txt"
    else:
        gobuster_filename = f"tcp_{str(libnmap_service.port)}_http_gobuster.txt"
    try:
        with open(os.path.abspath(os.path.join(scans_dir, gobuster_filename))) as f: 
            gobuster_scan = f.read()
        ET.SubElement(gobuster_node, "rich_text").text = gobuster_scan
    except IOError as error:
        print(error)
    nikto_node = ET.SubElement(parent_node, "node", foreground="", is_bold="False", name="nikto", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1
    if libnmap_service.port == 443:
        nikto_filename = f"tcp_{str(libnmap_service.port)}_https_nikto.txt"
    else:
        nikto_filename = f"tcp_{str(libnmap_service.port)}_http_nikto.txt"
    try:
        with open(os.path.abspath(os.path.join(scans_dir, nikto_filename))) as f: 
            nikto_scan = f.read()
        ET.SubElement(nikto_node, "rich_text").text = nikto_scan
    except IOError as error:
        print(error)
    if libnmap_service.port == 443:
        sslscan_node = ET.SubElement(parent_node, "node", foreground="", is_bold="False", name="sslscan", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
        uid += 1
        sslscan_filename = f"tcp_{str(libnmap_service.port)}_sslscan.txt"
        try:
            with open(os.path.abspath(os.path.join(scans_dir, sslscan_filename))) as f: 
                ssl_scan = f.read()
            ET.SubElement(sslscan_node, "rich_text").text = ssl_scan
        except IOError as error:
            print(error)
    return uid


def create_postex_node(parent_node, uid, node_name="Post Exploitation"):
    postex_node = ET.SubElement(parent_node, "node", custom_icon_id="0", foreground="", is_bold="False", name="Post Exploitation", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1
    ET.SubElement(postex_node, "node", custom_icon_id="0", foreground="", is_bold="False", name="Users & Groups", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1
    ET.SubElement(postex_node, "node", custom_icon_id="0", foreground="", is_bold="False", name="System Info", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1
    ET.SubElement(postex_node, "node", custom_icon_id="0", foreground="", is_bold="False", name="Processes", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1 
    ET.SubElement(postex_node, "node", custom_icon_id="0", foreground="", is_bold="False", name="Network Info", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1
    ET.SubElement(postex_node, "node", custom_icon_id="0", foreground="", is_bold="False", name="Installed Applications", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1
    ET.SubElement(postex_node, "node", custom_icon_id="0", foreground="", is_bold="False", name="Jobs", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1
    return uid, postex_node


def create_privesc_node(parent_node, uid, node_name="Privesc"):
    privesc_node = ET.SubElement(parent_node, "node", custom_icon_id="30", foreground="", is_bold="False", name=node_name, prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1
    ET.SubElement(privesc_node, "node", custom_icon_id="18", foreground="", is_bold="False", name="Notes", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1
    ET.SubElement(privesc_node, "node", custom_icon_id="44", foreground="", is_bold="False", name="Script Results", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1
    ET.SubElement(privesc_node, "node", custom_icon_id="0", foreground="", is_bold="False", name="Permissions", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1
    return uid


def create_loot_node(parent_node, uid, node_name="Loot"):
    loot_node = ET.SubElement(parent_node, "node", custom_icon_id="0", foreground="", is_bold="False", name="Loot", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1
    ET.SubElement(loot_node, "node", custom_icon_id="18", foreground="", is_bold="False", name="Creds", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1
    ET.SubElement(loot_node, "node", custom_icon_id="18", foreground="", is_bold="False", name="Hashes", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1
    ET.SubElement(loot_node, "node", custom_icon_id="18", foreground="", is_bold="False", name="Flags", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1
    return uid


def yes_or_no(prompt):
    response = ''
    while response != 'y' and response != 'n':
        response = input(str(prompt)).lower()
    if response == 'y':
        return True
    else:
        return False


def get_service_string(libnmap_service):
    try:
        service_string = services_dict[libnmap_service.service]
    except KeyError:
        service_string = libnmap_service.service
    return service_string


def create_empty_ctd():
    uid = 1
    root_node = ET.Element("cherrytree")
    title_node = ET.SubElement(root_node, "node", custom_icon_id="0", foreground="", is_bold="False", name=args.output_file, prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1
    ET.SubElement(title_node, "node", custom_icon_id="0", foreground="", is_bold="False", name="Service Enumeration", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1
    uid, postex_node = create_postex_node(title_node, uid)
    uid = create_privesc_node(postex_node, uid, "Privesc (User)")
    uid = create_privesc_node(postex_node, uid, "Privesc (Root)")
    uid = create_loot_node(title_node, uid)
    tree = ET.ElementTree(root_node)
    tree.write(os.path.splitext(args.output_file)[0] + ".ctd")


def create_ctd(autorecon_dir):
    scans_dir = os.path.abspath(os.path.join(autorecon_dir, "scans/"))
    if not os.path.isdir(scans_dir):
        print(f"'{os.path.abspath(args.dir)}' does not appear to be a valid AutoRecon directory.")
        print("A valid AutoRecon target directory should contain a /scans subdirectory.")
        return
    tcp_scans_exist, udp_scans_exist = True, True
    nmap_tcp_file = os.path.abspath(os.path.join(scans_dir, "_full_tcp_nmap.txt"))
    nmap_tcp_xml_file = os.path.abspath(os.path.join(scans_dir, "xml/_full_tcp_nmap.xml"))
    nmap_udp_file = os.path.abspath(os.path.join(scans_dir, "_top_20_udp_nmap.txt"))
    nmap_udp_xml_file = os.path.abspath(os.path.join(scans_dir, "xml/_top_20_udp_nmap.xml"))

    if not all([os.path.isfile(nmap_tcp_xml_file), os.path.isfile(nmap_tcp_file)]):
        user_resp = yes_or_no("Nmap TCP scan files are missing. Create template anyway? [y/n]\n")
        if user_resp:
            tcp_scans_exist = False
        else:
            return
    if not all([os.path.isfile(nmap_udp_file), os.path.isfile(nmap_udp_xml_file)]):
        user_resp = yes_or_no("Nmap UDP scan files are missing. Create template anyway? [y/n]\n")
        if user_resp:
            udp_scans_exist = False
        else:
            return

    uid = 1
    root_node = ET.Element("cherrytree")
    title_node = ET.SubElement(root_node, "node", custom_icon_id="0", foreground="", is_bold="False", name=args.output_file, prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1
    service_enum_node = ET.SubElement(title_node, "node", custom_icon_id="0", foreground="", is_bold="False", name="Service Enumeration", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1

    if tcp_scans_exist:
        try:
            tcp_report = NmapParser.parse_fromfile(nmap_tcp_xml_file)
        except:
            print("Error while parsing nmap TCP scan file: " + nmap_tcp_xml_file)
    if udp_scans_exist:
        try:
            udp_report = NmapParser.parse_fromfile(nmap_udp_xml_file)
        except:
            print("Error while parsing nmap UDP scan file: " + nmap_udp_xml_file)
    try:
        with open(nmap_tcp_file) as f:
            nmap_scan = f.read()
        ET.SubElement(service_enum_node, "rich_text").text = nmap_scan
    except IOError as error:
        print(error)

    ET.SubElement(service_enum_node, "node", custom_icon_id="18", foreground="", is_bold="False", name="Notes", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid += 1

    if tcp_scans_exist:
        host = tcp_report.hosts[0]
        if (not host.is_up() or len(host.services) == 0):
            return
        open_tcp_ports = [libnmap_service for libnmap_service in host.services if libnmap_service.open()]
        for libnmap_service in open_tcp_ports:
            uid += create_tcp_service_node(libnmap_service, scans_dir, service_enum_node, uid)

    if udp_scans_exist:
        host = udp_report.hosts[0]
        if (not host.is_up() or len(host.services) == 0):
            return
        open_udp_ports = [libnmap_service for libnmap_service in host.services if libnmap_service.open()]
        for libnmap_service in open_udp_ports:
            uid += create_udp_service_node(libnmap_service, scans_dir, service_enum_node, uid)

    uid, postex_node = create_postex_node(title_node, uid)
    uid = create_privesc_node(postex_node, uid, "Privesc (User)")
    uid = create_privesc_node(postex_node, uid, "Privesc (Root)")
    uid = create_loot_node(title_node, uid)
    tree = ET.ElementTree(root_node)
    tree.write(os.path.splitext(args.output_file)[0] + ".ctd")


def main():
    if args.output_file == 'autocherry' and os.path.exists('autocherry.ctd'):
        if not yes_or_no("File 'autocherry.ctd' already exists in this directory. Overwrite? [y/n]\n"):
            return
    if args.dir is not None:
        create_ctd(args.dir)
    elif args.empty:
        create_empty_ctd()


if __name__ == "__main__":
    main()
