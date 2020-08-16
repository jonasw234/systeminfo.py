#!/usr/bin/env python3
"""
Generates systeminfo-like output from offline images

Usage: systeminfo.py -p MOUNTPOINT

Options:
    -p MOUNTPOINT --mountpoint=MOUNTPOINT  Search for the needed registry hives (SYSTEM and SOFTWARE) underneath this path
"""
from datetime import datetime
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
    system_hive_dict['manufacturer'] = system_hive.get_key(f'SYSTEM\HardwareConfig\{current_hardware_config}').get_value('SystemManufacturer')
    system_hive_dict['model'] = system_hive.get_key(f'SYSTEM\HardwareConfig\{current_hardware_config}').get_value('SystemProductName')
    system_hive_dict['type'] = system_hive.get_key(f'{current_control_set}\Enum\ROOT\ACPI_HAL\\0000').get_value('DeviceDesc').split(';')[1].replace('ACPI ', '')
    return system_hive_dict


def parse_software_hive(software_hive: RegistryHive) -> dict:
    """
    Parse software hive and return needed information.

    Input
    -----
    software_hive: RegistryHive
        The software hive to parse

    Return
    ------
    dict
        Dictionary with the information for systeminfo
    """
    software_hive_dict = {'registered_owner': software_hive.get_key('Software\Microsoft\Windows NT\CurrentVersion').get_value('RegisteredOwner')}
    software_hive_dict['os_name'] = ' '.join(['Microsoft', software_hive.get_key('Software\Microsoft\Windows NT\CurrentVersion').get_value('ProductName')])
    software_hive_dict['os_build_type'] = software_hive.get_key('Software\Microsoft\Windows NT\CurrentVersion').get_value('CurrentType')
    software_hive_dict['product_id'] = software_hive.get_key('Software\Microsoft\Windows NT\CurrentVersion').get_value('ProductId')
    software_hive_dict['install_date'] = software_hive.get_key('Software\Microsoft\Windows NT\CurrentVersion').get_value('InstallDate')  # UTC, Needs timezone offset
    software_hive_dict['hotfix'] = set(hotfix.get_value('InstallName').split('_for_')[1].split('~')[0] for hotfix in software_hive.get_key('Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages').iter_subkeys() if '_for_KB' in hotfix.get_value('InstallName') and hotfix.get_value('CurrentState') == 112)  # 112 is successfully installed
    software_hive_dict['hotfix'].update(set(hotfix.get_value('InstallLocation').split('-')[1] for hotfix in software_hive.get_key('Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages').iter_subkeys() if 'RollupFix' in hotfix.get_value('InstallName') and hotfix.get_value('CurrentState') == 112))  # 112 is successfully installed
    return software_hive_dict


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
    systeminfo = parse_system_hive(system_hive)
    systeminfo.update(parse_software_hive(software_hive))
    output = f"""Host Name:                 {systeminfo['hostname']}
OS Name:                   {systeminfo['os_name']}
OS Version:                10.0.17134 N/A Build 17134
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             {systeminfo['os_build_type']}
Registered Owner:          {systeminfo['registered_owner']}
Registered Organization:
Product ID:                {systeminfo['product_id']}
Original Install Date:     {systeminfo['install_date']}  # TODO Add timezone offset and convert string
System Boot Time:          0-0-0000, 00:00:00
System Manufacturer:       {systeminfo['manufacturer']}
System Model:              {systeminfo['model']}
System Type:               {systeminfo['type']}
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 78 Stepping 3 GenuineIntel ~2396 Mhz
BIOS Version:              {systeminfo['bios_version']}
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               {systeminfo['boot_device']}
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+01:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna
Total Physical Memory:     16.265 MB
Available Physical Memory: 5.160 MB
Virtual Memory: Max Size:  18.697 MB
Virtual Memory: Available: 4.793 MB
Virtual Memory: In Use:    13.904 MB
Page File Location(s):     """
    padding = ''
    for page_file_location in systeminfo['page_file_locations']:
        output += f'{padding}{page_file_location}\n'
        padding = '                           '
    output += f"""Domain:                    {systeminfo['domain']}
Logon Server:              \\LAPTOP
Hotfix(s):                 {len(systeminfo['hotfix'])} Hotfix(s) Installed.
"""
    for idx, hotfix in enumerate(systeminfo['hotfix'], start=1):
        output += f'                           [{str(idx).zfill(2)}]: {hotfix}\n'
    output += """Network Card(s):           6 NIC(s) Installed.
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
    print(output)


if __name__ == '__main__':
    main()
