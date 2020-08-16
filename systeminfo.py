#!/usr/bin/env python3
"""
Generates systeminfo-like output from offline images

Usage: systeminfo.py -p MOUNTPOINT

Options:
    -p MOUNTPOINT --mountpoint=MOUNTPOINT  Search for the needed registry hives (SYSTEM and SOFTWARE) underneath this path
"""
from datetime import datetime, timedelta
import os
import sys

from docopt import docopt
from regipy.registry import RegistryHive


def determine_current_control_set(system_hive: RegistryHive) -> str:
    """
    Determine the current control set.

    Input
    -----
    system_hive: RegistryHive
        The system hive to parse

    Return
    ------
    str
        The path to the current control set
    """
    current_control_set = system_hive.get_key('\\Select').get_value('Current')
    for control_set in system_hive.CONTROL_SETS:
        if int(control_set[-3:]) == current_control_set:
            current_control_set = control_set
            break
    else:
        raise ValueError('Error determining current control set.')
    return current_control_set


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
    current_control_set = determine_current_control_set(system_hive)
    # Determine current hardware config
    current_hardware_config = system_hive.get_key('SYSTEM\HardwareConfig').get_value('LastConfig')

    # Hostname
    system_hive_dict = {'hostname': system_hive.get_key(f'{current_control_set}\Services\Tcpip\Parameters').get_value('Hostname')}

    # BIOS Version
    bios_version = system_hive.get_key(f"SYSTEM\HardwareConfig\{current_hardware_config}").get_value('BIOSVersion')
    bios_vendor = system_hive.get_key(f"SYSTEM\HardwareConfig\{current_hardware_config}").get_value('BIOSVendor')
    bios_release_date = system_hive.get_key(f"SYSTEM\HardwareConfig\{current_hardware_config}").get_value('BIOSReleaseDate')
    system_hive_dict['bios_version'] = f'{bios_vendor} {bios_version}, {bios_release_date}'

    # Domain
    system_hive_dict['domain'] = system_hive.get_key(f'{current_control_set}\Services\Tcpip\Parameters').get_value('Domain')
    system_hive_dict['domain'] = system_hive_dict['domain'] if system_hive_dict['domain'] != 0 else 'WORKGROUP'

    # Page file locations
    system_hive_dict['page_file_locations'] = system_hive.get_key(f'{current_control_set}\Control\Session Manager\Memory Management').get_value('PagingFiles')[::3]
    # TODO This could probably be improved if I could find the system drive letter in the registry
    for idx, page_file_location in enumerate(system_hive_dict['page_file_locations']):
        if page_file_location[0] == '?':
            system_hive_dict['page_file_locations'][idx] = page_file_location.replace('?', system_hive.get_key(f'{current_control_set}\Control\Session Manager\Memory Management').get_value('ExistingPageFiles')[0][4])

    # Boot device
    system_hive_dict['boot_device'] = system_hive.get_key('SYSTEM\Setup').get_value('SystemPartition')

    # System manufacturer
    system_hive_dict['manufacturer'] = system_hive.get_key(f'SYSTEM\HardwareConfig\{current_hardware_config}').get_value('SystemManufacturer')

    # System model
    system_hive_dict['model'] = system_hive.get_key(f'SYSTEM\HardwareConfig\{current_hardware_config}').get_value('SystemProductName')

    # System type
    system_hive_dict['type'] = system_hive.get_key(f'{current_control_set}\Enum\ROOT\ACPI_HAL\\0000').get_value('DeviceDesc').split(';')[1].replace('ACPI ', '')

    # Network adapters
    # MAC address can optionally be changed with NetworkAddress entry
    network_adapters = dict()
    for network_adapter in system_hive.get_key(''.join([current_control_set, '\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'])).iter_subkeys():
        if network_adapter.get_value('NetCfgInstanceId'):
            network_adapters[network_adapter.get_value('NetCfgInstanceId')] = (network_adapter.get_value('DriverDesc'), network_adapter.get_value('NetworkAddress'))
    interfaces = dict()
    for interface in system_hive.get_key(''.join([current_control_set, '\Services\Tcpip\Parameters\Interfaces'])).iter_subkeys():
        if not network_adapters.get(interface.name.upper()):
            continue
        interfaces[interface.name] = {
                'desc': network_adapters[interface.name.upper()][0],
                'mac': network_adapters[interface.name.upper()][1],
                'dhcp_activated': interface.get_value('EnableDHCP') == 1,
                'dhcp_server': interface.get_value('DhcpServer'),
                'ip_addresses': [interface.get_value('DhcpIPAddress')] if interface.get_value('DhcpIPAddress') else interface.get_value('IPAddress')
        }
        if not interfaces[interface.name]['ip_addresses']:
            del interfaces[interface.name]
    system_hive_dict['network_cards'] = interfaces

    # Processor(s)
    system_hive_dict['processors'] = system_hive.get_key(f'{current_control_set}\Control\Session Manager\Environment').get_value('PROCESSOR_IDENTIFIER')  # This is technically not correct, because the real value is in the volatile HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor subkeys

    # Windows/System directory
    lsa_library = system_hive.get_key(f'{current_control_set}\Services\Lsa\Performance').get_value('Library')
    system_hive_dict['windows_directory'] = '\\'.join(lsa_library.split('\\')[:2])
    system_hive_dict['system_directory'] = '\\'.join(lsa_library.split('\\')[:3])

    # Return results
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
    # Registered owner
    software_hive_dict = {'registered_owner': software_hive.get_key('Software\Microsoft\Windows NT\CurrentVersion').get_value('RegisteredOwner')}

    # OS name
    software_hive_dict['os_name'] = ' '.join(['Microsoft', software_hive.get_key('Software\Microsoft\Windows NT\CurrentVersion').get_value('ProductName')])

    # OS build type
    software_hive_dict['os_build_type'] = software_hive.get_key('Software\Microsoft\Windows NT\CurrentVersion').get_value('CurrentType')

    # Product ID
    software_hive_dict['product_id'] = software_hive.get_key('Software\Microsoft\Windows NT\CurrentVersion').get_value('ProductId')

    # Install date
    software_hive_dict['install_date'] = software_hive.get_key('Software\Microsoft\Windows NT\CurrentVersion').get_value('InstallDate')  # UTC, Needs timezone offset

    # Hotfixes
    software_hive_dict['hotfix'] = set(hotfix.get_value('InstallName').split('_for_')[1].split('~')[0] for hotfix in software_hive.get_key('Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages').iter_subkeys() if '_for_KB' in hotfix.get_value('InstallName') and hotfix.get_value('CurrentState') == 112)  # 112 is successfully installed
    software_hive_dict['hotfix'].update(set(hotfix.get_value('InstallLocation').split('-')[1] for hotfix in software_hive.get_key('Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages').iter_subkeys() if 'RollupFix' in hotfix.get_value('InstallName') and hotfix.get_value('CurrentState') == 112))  # 112 is successfully installed

    # OS Version
    software_hive_dict['os_version'] = ' '.join([software_hive.get_key('Software\Microsoft\Windows\CurrentVersion\Flighting\Build').get_value('OSVersion'), 'N/A Build', software_hive.get_key('Software\Microsoft\Windows NT\CurrentVersion').get_value('CurrentBuild')])

    # Registered organization
    software_hive_dict['registered_organization'] = software_hive.get_key('Software\Microsoft\Windows\CurrentVersion\Flighting\Build').get_value('RegisteredOrganization')

    # Return results
    return software_hive_dict


def parse_timezone_information(system_hive: RegistryHive, software_hive: RegistryHive) -> dict:
    """
    Parse system and software hives and return needed information.

    Input
    -----
    system_hive: RegistryHive
        The system hive to parse
    software_hive: RegistryHive
        The software hive to parse

    Return
    ------
    dict
        Dictionary with the information for systeminfo
    """
    # Determine current control set
    current_control_set = determine_current_control_set(system_hive)
    # Timezone information
    timezone_key_name = system_hive.get_key(f'{current_control_set}\Control\TimeZoneInformation').get_value('TimeZoneKeyName')
    timezone_information = {'timezone_desc': software_hive.get_key(f'Software\Microsoft\Windows NT\CurrentVersion\Time Zones\{timezone_key_name}').get_value('Display')}
    timezone_information['timezone_offset'] = timezone_information['timezone_desc'].split('+')[1].split(')')[0]

    # Return results
    return timezone_information


def main():
    """Find registry hives and invoke parsers."""
    # Parse command line arguments
    args = docopt(__doc__)
    if not os.path.isdir(args['--mountpoint']):
        print(f'Error: {args["--mountpoint"]} is not a directory.')
        sys.exit(1)

    # Read registry hives
    software_hive = None
    system_hive = None
    try:
        # System hive
        if os.path.isfile(os.path.join(args['--mountpoint'], 'SYSTEM')):
            system_hive = RegistryHive(os.path.join(args['--mountpoint'], 'SYSTEM'))
        elif os.path.isfile(os.path.join(args['--mountpoint'], 'Windows', 'config', 'SYSTEM')):
            system_hive = RegistryHive(os.path.join(args['--mountpoint'], 'Windows', 'config', 'SYSTEM'))
        else:
            print(f'Error: Neither {os.path.join(args["--mountpoint"], "SYSTEM")} nor {os.path.join(args["--mountpoint"], "Windows", "config", "SYSTEM")} seem to be correct.  Please set the mountpoint directly to the path for the registry hives.')
            sys.exit(1)
        # Software hive
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

    # Call parsing methods
    systeminfo = parse_system_hive(system_hive)
    systeminfo.update(parse_software_hive(software_hive))
    systeminfo.update(parse_timezone_information(system_hive, software_hive))

    # Prepare systeminfo-like output
    output = f"""Host Name:                 {systeminfo['hostname'].upper()}
OS Name:                   {systeminfo['os_name']}
OS Version:                {systeminfo['os_version']}
OS Manufacturer:           Microsoft Corporation *
OS Configuration:          Standalone Workstation *
OS Build Type:             {systeminfo['os_build_type']}
Registered Owner:          {systeminfo['registered_owner']}
Registered Organization:   {systeminfo['registered_organization'] if systeminfo['registered_organization'] else ''}
Product ID:                {systeminfo['product_id']}
Original Install Date:     {(datetime.fromtimestamp(systeminfo['install_date']) + timedelta(hours=int(systeminfo['timezone_offset'].split(':')[0]), minutes=int(systeminfo['timezone_offset'].split(':')[1]))).strftime('%d-%m-%Y, %H:%M:%S')}
System Boot Time:          0-0-0000, 00:00:00
System Manufacturer:       {systeminfo['manufacturer']}
System Model:              {systeminfo['model']}
System Type:               {systeminfo['type']}
Processor(s):              1 Processor(s) Installed.
                           [01]: {systeminfo['processors']}
BIOS Version:              {systeminfo['bios_version']}
Windows Directory:         {systeminfo['windows_directory']}
System Directory:          {systeminfo['system_directory']}
Boot Device:               {systeminfo['boot_device']}
System Locale:             en-us;English (United States) *
Input Locale:              en-us;English (United States) *
Time Zone:                 {systeminfo['timezone_desc']}
Total Physical Memory:     16.265 MB *
Available Physical Memory: 5.160 MB *
Virtual Memory: Max Size:  18.697 MB *
Virtual Memory: Available: 4.793 MB *
Virtual Memory: In Use:    13.904 MB *
Page File Location(s):     """
    padding = ''
    for page_file_location in systeminfo['page_file_locations']:
        output += f'{padding}{page_file_location}\n'
        padding = '                           '
    output += f"""Domain:                    {systeminfo['domain']}
Logon Server:              \\\\UNKNOWN
Hotfix(s):                 {len(systeminfo['hotfix'])} Hotfix(s) Installed.
"""
    for idx, hotfix in enumerate(systeminfo['hotfix'], start=1):
        output += f'                           [{str(idx).zfill(2)}]: {hotfix}\n'
    output += f'Network Card(s):           {len(systeminfo["network_cards"])} NIC(s) Installed.'
    for idx, network_card in enumerate(systeminfo['network_cards'].values(), start=1):
        output += f"""
                           [{str(idx).zfill(2)}]: {network_card['desc']}
                                 Connection Name: UNKNOWN *
                                 DHCP Enabled:    {'Yes' if network_card['dhcp_activated'] else 'No'}
                                 IP address(es)"""
        for idx2, ip_address in enumerate(network_card['ip_addresses'], start=1):
            output += f'\n                                 [{str(idx2).zfill(2)}]: {ip_address}'
    output += """
Hyper-V Requirements:      VM Monitor Mode Extensions: Yes *
                           Virtualization Enabled In Firmware: Yes *
                           Second Level Address Translation: Yes *
                           Data Execution Prevention Available: Yes *
"""
    print(output)


if __name__ == '__main__':
    main()
