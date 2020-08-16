# systeminfo.py
Sometimes it can be useful to get some output about an offline system the way you would by running the `systeminfo` command on an online system, but you don’t want to start the system for whatever reason.

A while ago at work we were doing some incident response and tried to figure out how an attacker got access to the system we were given by our customer.  In situations like these running the [Windows Exploit Suggester - Next Generation (WES-NG)](https://github.com/bitsadmin/wesng) can give some great information about missing hotfixes that could have been used as entry points.  
Having to turn the disk image into a virtual machine, circumventing the login if you don’t have local credentials etc. takes valuable time, so staying inside the (usually Linux based) analysis station can be useful to save time and focus on other parts of the investigation.

To use this tool just point it to either the mount point for the image or the path to the SYSTEM and SOFTWARE hives directly (usually `Windows/config`), e.g.
`systeminfo.py -p /mnt/case01`

## Installation
Installation is done with [Pipenv](https://pipenv.pypa.io/en/latest/).  Install with:
```
git clone https://github.com/jonasw234/systeminfo.py
cd systeminfo.py
pipenv install
```
or if you want to help with development, use `pipenv install --dev` instead.

## Limitations
Some information is not stored persistently and can thus not be determined with certainty.  
Where applicable I have implemented workarounds to get similar information, but you need to verify the following entries yourself if you need certainty:
- Processor(s): Should be read from the volatile key `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor`, but I have found `HKLM\System\CurrentControlSet\Control\Session Manager\Environment\PROCESSOR_IDENTIFIER` to hold similar information
- Logon server: Should be read from the volatile key `HKCU\Volatile Environment\LOGONSERVER`, I have not found any suitable alternatives yet
- Windows/System directory: I could not find where the data is originally read from, so I opted to use `HKLM\SYSTEM\ControlSet001\Services\Lsa\Performance\Library` as a path that should exist on all Windows versions and parsed the data from that
- NICs: I couldn’t find the IPv6 addresses in the registry, so only IPv4 will be printed
- Virtual Memory: Max Size: Automatic page file size is determined at runtime, so I decided to sum the fixed max sizes and add `+ x` if there are also automatically determined sizes
