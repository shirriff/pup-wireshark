# Wireshark support for Xerox Alto PUP packets #

Install pup.lua in the Wireshark plugins directory [details](https://www.wireshark.org/docs/wsug_html_chunked/ChAppFilesConfigurationSection.html).
On Windows, directory is %APPDATA%\Wireshark\plugins

This supports LCM's encapsulations: UDP packets on 42424 or Ethernet broadcast packets with type 0xbeef, and raw packets with wtap.USER0.
Work in progress: not all PUP packets are fully decoded.

PUP specification is [pupSpec.pdf](http://www.textfiles.com/bitsavers/pdf/xerox/alto/pupSpec.pdf).

Wireshark recommendations:
*  Disable View -> Colorize packet list, which grays out broadcast packets
*  If you change this file, Control-Shift-L to reload Lua code

Ken Shirriff, http://righto.com

Git Repository: https://github.com/shirriff/pup-wireshark
