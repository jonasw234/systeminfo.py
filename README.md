# systeminfo.py
Sometimes it can be useful to get some output about an offline system the way you would by running the `systeminfo` command on an online system, but you don’t want to start the system for whatever reason.

A while ago at work we were doing some incident response and tried to figure out how an attacker got access to the system we were given by our customer.  In situations like these running the [Windows Exploit Suggester - Next Generation (WES-NG)](https://github.com/bitsadmin/wesng) can give some great information about missing hotfixes that could have been used as entry points.  
Not having to have to turn the disk image into a virtual machine, circumvent the login if you don’t have it, etc. takes valuable time, so staying inside the (usually Linux based) analysis station can be useful to save time and focus on other parts of the investigation.

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
