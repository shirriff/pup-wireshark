# Wireshark support for Xerox Alto PUP packets #

The Xerox Alto computer from the 1970s used PUP protocol for its Ethernet. 
This Wireshark plugin decodes PUP packets and related packets used by the Alto.
The PUP specification is [here](http://www.textfiles.com/bitsavers/pdf/xerox/alto/pupSpec.pdf).

For more information on the Alto, see my [blog posts](http://www.righto.com/search/label/alto) on the Alto.

If you're interested in this, you probably are interested in the Living Computer Museum's [Contralto emulator](https://github.com/livingcomputermuseum/ContrAlto) and [IFS](https://github.com/livingcomputermuseum/IFS) (Interim File System).
This plugin supports LCM's encapsulations: UDP packets on 42424 or Ethernet broadcast packets with type 0xbeef, and raw packets with wtap.USER0.

To use this plugin, install pup.lua in the Wireshark plugins directory [details](https://www.wireshark.org/docs/wsug_html_chunked/ChAppFilesConfigurationSection.html).
On Windows, directory is %APPDATA%\Wireshark\plugins

Wireshark tips:
*  Disable View -> Colorize packet list, which grays out broadcast packets
*  If you change this file, Control-Shift-L to reload Lua code

This is a work in progress: not all PUP packets are fully decoded.

Ken Shirriff, http://righto.com

Git Repository: https://github.com/shirriff/pup-wireshark
