#!/usr/bin/env python3
"""
Generates systeminfo-like output from offline images

Usage: systeminfo.py -p MOUNTPOINT

Options:
    -p MOUNTPOINT --mountpoint=MOUNTPOINT  Search for the needed registry hives (SYSTEM and SOFTWARE) underneath this path
"""
import os
import sys

from docopt import docopt
from regipy.registry import RegistryHive


def parse_system_hive(system_hive: RegistryHive) -> dict:
    """
    Parse system hive and return needed information.

    Input
    -----
    system_hive: RegistryHive
        The system hive to parse

    Return
    ------
    dict
        Dictionary with the information for systeminfo
    """
    # Determine current control set
    current_control_set = system_hive.get_key('\\Select').get_value('Current')
    for control_set in system_hive.CONTROL_SETS:
        if int(control_set[-3:]) == current_control_set:
            current_control_set = control_set
            break
    else:
        raise ValueError('Error determining current control set.')
    system_hive_dict = {'hostname': system_hive.get_key(f'{current_control_set}\Services\Tcpip\Parameters').get_value('Hostname')}
    current_hardware_config = system_hive.get_key('SYSTEM\HardwareConfig').get_value('LastConfig')
    bios_version = system_hive.get_key(f"SYSTEM\HardwareConfig\{current_hardware_config}").get_value('BIOSVersion')
    bios_vendor = system_hive.get_key(f"SYSTEM\HardwareConfig\{current_hardware_config}").get_value('BIOSVendor')
    bios_release_date = system_hive.get_key(f"SYSTEM\HardwareConfig\{current_hardware_config}").get_value('BIOSReleaseDate')
    system_hive_dict['bios_version'] = f'{bios_vendor} {bios_version}, {bios_release_date}'
    system_hive_dict['domain'] = system_hive.get_key(f'{current_control_set}\Services\Tcpip\Parameters').get_value('Domain')
    system_hive_dict['domain'] = system_hive_dict['domain'] if system_hive_dict['domain'] != 0 else 'WORKGROUP'
    system_hive_dict['page_file_locations'] = system_hive.get_key(f'{current_control_set}\Control\Session Manager\Memory Management').get_value('PagingFiles')[::3]
    # TODO This could probably be improved if I could find the system drive letter in the registry
    for idx, page_file_location in enumerate(system_hive_dict['page_file_locations']):
        if page_file_location[0] == '?':
            system_hive_dict['page_file_locations'][idx] = page_file_location.replace('?', system_hive.get_key(f'{current_control_set}\Control\Session Manager\Memory Management').get_value('ExistingPageFiles')[0][4])
    system_hive_dict['boot_device'] = system_hive.get_key('SYSTEM\Setup').get_value('SystemPartition')


def main():
    """Find registry hives and invoke parsers."""
    # Parse command line arguments
    args = docopt(__doc__)
    if not os.path.isdir(args['--mountpoint']):
        print(f'Error: {args["--mountpoint"]} is not a directory.')
        sys.exit(1)
    software_hive = None
    system_hive = None
    try:
        if os.path.isfile(os.path.join(args['--mountpoint'], 'SYSTEM')):
            system_hive = RegistryHive(os.path.join(args['--mountpoint'], 'SYSTEM'))
        elif os.path.isfile(os.path.join(args['--mountpoint'], 'Windows', 'config', 'SYSTEM')):
            system_hive = RegistryHive(os.path.join(args['--mountpoint'], 'Windows', 'config', 'SYSTEM'))
        else:
            print(f'Error: Neither {os.path.join(args["--mountpoint"], "SYSTEM")} nor {os.path.join(args["--mountpoint"], "Windows", "config", "SYSTEM")} seem to be correct.  Please set the mountpoint directly to the path for the registry hives.')
            sys.exit(1)
        if os.path.isfile(os.path.join(args['--mountpoint'], 'SOFTWARE')):
            software_hive = RegistryHive(os.path.join(args['--mountpoint'], 'SOFTWARE'))
        elif os.path.isfile(os.path.join(args['--mountpoint'], 'Windows', 'config', 'SOFTWARE')):
            software_hive = RegistryHive(os.path.join(args['--mountpoint'], 'Windows', 'config', 'SOFTWARE'))
        else:
            print(f'Error: Neither {os.path.join(args["--mountpoint"], "SOFTWARE")} nor {os.path.join(args["--mountpoint"], "Windows", "config", "SOFTWARE")} seem to be correct.  Please set the mountpoint directly to the path for the registry hives.')
            sys.exit(1)
    except ConstError:
        print('Invalid registry hives found.')
        sys.exit(1)
    system_hive_dict = parse_system_hive(system_hive)


if __name__ == '__main__':
    main()
"""
# Host Name:                 LAPTOP
OS Name:                   Microsoft Windows 10 Education
OS Version:                10.0.17134 N/A Build 17134
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00328-00251-17473-AA323
Original Install Date:     30-4-2018, 22:22:37
System Boot Time:          6-9-2018, 08:20:07
System Manufacturer:       HP
System Model:              HP EliteBook 840 G3
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 78 Stepping 3 GenuineIntel ~2396 Mhz
# BIOS Version:              HP N75 Ver. 01.29, 4-6-2018
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
# Boot Device:               \Device\HarddiskVolume7
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+01:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna
Total Physical Memory:     16.265 MB
Available Physical Memory: 5.160 MB
Virtual Memory: Max Size:  18.697 MB
Virtual Memory: Available: 4.793 MB
Virtual Memory: In Use:    13.904 MB
# Page File Location(s):     C:\pagefile.sys
# Domain:                    WORKGROUP
Logon Server:              \\LAPTOP
Hotfix(s):                 5 Hotfix(s) Installed.
                           [01]: KB4100347
                           [02]: KB4338832
                           [03]: KB4343669
                           [04]: KB4343902
                           [05]: KB4343909
Network Card(s):           6 NIC(s) Installed.
                           [01]: TAP-Windows Adapter V9
                                 Connection Name: Ethernet 2
                                 Status:          Media disconnected
                           [02]: VMware Virtual Ethernet Adapter for VMnet1
                                 Connection Name: VMware Network Adapter VMnet1
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 192.168.150.1
                                 [02]: fe80::8900:6f73:9629:d8f3
                           [03]: VMware Virtual Ethernet Adapter for VMnet8
                                 Connection Name: VMware Network Adapter VMnet8
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 192.168.159.1
                                 [02]: fe80::984a:e9de:308b:2457
                           [04]: Intel(R) Ethernet Connection I219-LM
                                 Connection Name: Ethernet
                                 Status:          Media disconnected
                           [05]: Intel(R) Dual Band Wireless-AC 8260
                                 Connection Name: Wi-Fi
                                 DHCP Enabled:    Yes
                                 DHCP Server:     192.168.1.1
                                 IP address(es)
                                 [01]: 192.168.1.57
                                 [02]: fe80::391d:20cc:b273:851c
                           [06]: Generic Mobile Broadband Adapter
                                 Connection Name: Cellular
                                 Status:          Media disconnected
Hyper-V Requirements:      VM Monitor Mode Extensions: Yes
                           Virtualization Enabled In Firmware: Yes
                           Second Level Address Translation: Yes
                           Data Execution Prevention Available: Yes
"""
