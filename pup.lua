-- Wireshark support for Xerox Alto PUP packets.

-- Install this file in the Wireshark plugins directory, https://www.wireshark.org/docs/wsug_html_chunked/ChAppFilesConfigurationSection.html
-- On Windows: %APPDATA%\Wireshark\plugins
--
-- This supports LCM's encapsulations: UDP packets on 42424 or Ethernet broadcast packets with type 0xbeef, and raw packets with wtap.USER0.
-- Work in progress: not all PUP packets are fully decoded.
--
-- PUP specification is at http://www.textfiles.com/bitsavers/pdf/xerox/alto/pupSpec.pdf
--
-- Wireshark recommendations:
--   Disable View -> Colorize packet list, which grays out broadcast packets
--   If you change this file, Control-Shift-L to reload Lua code
--
-- Ken Shirriff, http://righto.com

-- types from http://xeroxalto.computerhistory.org/_cd8_/pup/.netconstants.bravo!4.html
local ethertypes = {
  [258]= 'Peek Report',  -- 0402
  [386]= 'Breath of Life',  -- 0602
  [448]= 'Echo Me',  -- 0700
  [449]= 'ImAnEcho',  -- 0701
  [512]= 'Pupdatagraph',  -- 01000
  [513]= 'DOD IP Datagram',  -- 01001
  [514]= 'DOD IP address resolution',  -- 01002
  [516]= 'DOD IP host to Arpanet',  -- 01004
  [517]= 'Arpanet frontend to DOD IP host',  -- 01005
  [1024]= 'Ether MCA',  -- 02000
  [1536]= 'NS datagram transport',  -- 03000
  [1537]= '48 to 8',  -- 03001
  [4096]= 'Trek',  -- 010000
}

-- Dissector for xeth
-- xeth is my name for Xerox's 3mb/s Ethernet protocol, with 4-byte header.
-- This is different from standard Ethernet
local xeth = Proto("xeth", "Xerox Ethernet Protocol")
local xeth_dest = ProtoField.uint8 ("xeth.dest", "Dest", base.OCT)
local xeth_src = ProtoField.uint8 ("xeth.src", "Src", base.OCT)
local xeth_type = ProtoField.uint16 ("xeth.type", "Type", base.OCT, ethertypes)
xeth.fields = { xeth_dest, xeth_src, xeth_type }
function xeth.dissector(tvbuf,pinfo,root)
  pinfo.cols.dst = tvbuf(0,1):uint()
  pinfo.cols.src = tvbuf(1,1):uint()
  pinfo.cols.protocol:set("XETH")
  local tree = root:add(xeth, tvbuf:range(0,pktlen))
  -- local subtree = tree:add(xeth,tvbuf(),"Xerox Ethernet Protocol Data")
  local type = tvbuf(2,2):uint()
  if ethertypes[type] ~= nil then
    pinfo.cols.protocol:set(ethertypes[type])
  else
    pinfo.cols.protocol:set("XETH")
  end
  tree:add(xeth_dest, tvbuf(0,1))
  tree:add(xeth_src, tvbuf(1,1))
  tree:add(xeth_type, tvbuf(2,2))
  DissectorTable.get("xeth"):try(type, tvbuf(4,tvbuf:len()-4):tvb(), pinfo, root)
end

-- Dissector for xeth with 6-byte header.
-- LCM Ethernet encapsulation has an additional 2-byte length field.
-- Enable with:
--   Contralto: System -> System Configuration -> Ethernet: Raw Ethernet / Local Area Connection
--   IFS: ifs.cfg: InterfaceType = raw, InterfaceName = Local Area Connection
-- In Wireshark: Filter on eth.type == 0xbeef to get just the Ethernet packets
local xeth6 = Proto("xeth6", "Xerox Ethernet Protocol LCM encapsulation")
local xeth6_length = ProtoField.uint16 ("xeth6.length", "Length", base.HEX)
xeth.fields = { xeth6_length }
function xeth6.dissector(tvbuf,pinfo,root)
  root:add(xeth6_length, tvbuf:range(0,2))
  local len = tvbuf:range(0,2):uint() * 2 -- Length from Ethernet encapsulation
  if len ~= tvbuf:len() - 2 then
     -- Encapsulation length doesn't match packet length
    pinfo.cols.info:set("Unexpected length " .. len .. " vs " .. tvbuf:len() -2)
  end
  xeth.dissector(tvbuf(2,len):tvb(), pinfo, root)
end

-- Send USER0 packets to xeth. These are generated from logs with text2pcap
-- https://delog.wordpress.com/2011/04/20/custom-dissector-for-ethertype-link-layer-and-ip-protocol/
local wtap_encap_table = DissectorTable.get("wtap_encap")
wtap_encap_table:add(wtap.USER0, xeth)
--
-- Send 0xbeef Ethernet (LCM Ethernet encapsulation) to xeth6
local ethertype_table = DissectorTable.get("ethertype")
ethertype_table:add(0xbeef, xeth6)
--
-- Dissector table for different types of xeth packets, to handle PUP, etc.
DissectorTable.new("xeth", "xeth", ftypes.UINT16)

-- LCM encapsulation on UDP 42424
-- Enable with:
--   Contralto: System -> System Configuration -> Ethernet: UDP / Local Area Connection
--   IFS: ifs.cfg: InterfaceType = UDP, InterfaceName = Local Area Connection, UDPPort = 42424
-- Note that only one binary can use UDP at a time
-- In Wireshark: Filter on udp.port == 42424
local lcm = Proto("lcm", "LCM Encapsulation")
function lcm.dissector(tvbuf,pinfo,root)
  local tree = root:add(lcm, tvbuf:range(0,pktlen))
  local len = tvbuf(0,2):uint()
  if 2 * len + 2 == tvbuf:len() or 2 * len + 1 == tvbuf:len() then
    tree:add(tvbuf(0,2),"Length: " .. tvbuf(0,2):uint())
  else
    tree:add(tvbuf(0,2),"Bad Length: " .. tvbuf(0,2):uint() .. " " .. len .. " " .. tvbuf:len())
  end
  xeth.dissector(tvbuf(2,datalen):tvb(), pinfo, root)
end
DissectorTable.get("udp.port"):add(42424, lcm)

-- Dissector for PUP packets
-- First, the differnet types of PUP packets
local puptypes = {
  [1]= "Echo Me",
  [2]= "I am Echo",
  [3]= "I am Bad Echo",
  [4]= "Error",
  [5]= "Trace",
  [8]= "RFC",  -- 010
  [9]= "Abort",  -- 011
  [10]= "End",  -- 012
  [11]= "End Reply",  -- 013
  [16]= "Data",  -- 020
  [17]= "AData",  -- 021
  [18]= "Ack",  -- 022
  [19]= "Mark",  -- 023
  [20]= "Interrupt",  -- 024
  [21]= "Interrupt Reply",  -- 025
  [22]= "AMark",  -- 026
  [24]= "EFTP Data",  -- 030
  [25]= "EFTP Ack",  -- 031
  [26]= "EFTP End",  -- 032
  [27]= "EFTP Abort",  -- 033
  -- http://xeroxalto.computerhistory.org/_cd8_/pup/.miscservices.bravo!1.html
  [128]= "Time req",  -- 0200
  [129]= "Time response",  -- 0201
  [130]= "Tenex time req",  -- 0202
  [131]= "Tenex time resp",  -- 0203
  [132]= "Alto time req",  -- 0204
  [133]= "Alto time resp",  -- 0205
  [134]= "Alto new time req",  -- 0206
  [135]= "Alto new time resp",  -- 0207
  [136]= "Mail check",  -- 0210
  [140]= "Mail check (Laurel)",  -- 0214
  [137]= "New mail exists",  -- 0211
  [138]= "No new mail exists",  -- 0212
  [139]= "No such mailbox",  -- 0213
  [144]= "Name request lookup",  -- 0220
  [145]= "Name lookup response",  -- 0221
  [146]= "Directory lookup error",  -- 0222
  [147]= "Address lookup req",  -- 0223
  [148]= "Address lookup resp",  -- 0224
  [152]= "Where is user req",  -- 0230
  [153]= "Where is user resp",  -- 0231
  [154]= "Where is user error",  -- 0232
  [160]= "Networkd directory version",  -- 0240
  [161]= "Network directory update req",  -- 0241
  [164]= "Send boot file req",  -- 0244
  [165]= "Boot directory req",  -- 0245
  [166]= "Boot directory resp",  -- 0246
  [168]= "Authenticate req",  -- 0250
  [169]= "Authenticate positive resp",  -- 0251
  [170]= "Authenticate negative resp",  -- 0252
  [182]= "Validate recipient req",  -- 0266
  [183]= "Validate recipient yes",  -- 0267
  [184]= "Validate recipient no",  -- 0270
  [128]= "Gateway Information Request",  -- 0200
  [129]= "Gateway Information Reply",  -- 0201
  [130]= "Gateway Information Error Reply",  -- 0202
  [131]= "Gateway Information Statistics Request",  -- 0203
  [132]= "Gateway Information Statistics Reply",  -- 0204
}

local pup = Proto("pup", "PUP Protocol")

local pup_length = ProtoField.uint16 ("pup.length", "Length")
local pup_transport = ProtoField.uint8 ("pup.transport", "Transport")
local pup_type = ProtoField.uint8 ("pup.type", "Type", base.OCT, puptypes)
local pup_id = ProtoField.uint32 ("pup.id", "ID", base.HEX)
local pup_checksum = ProtoField.uint16 ("pup.checksum", "Checksum", base.HEX)
pup.fields = { pup_length, pup_transport, pup_type, pup_id, pup_checksum }
function pup.dissector(tvbuf,pinfo,root)
  local tree = root:add(pup, tvbuf:range(0,pktlen))
  -- local subtree = tree:add(pup,tvbuf(),"Xerox Ethernet Protocol Data")
  tree:add(pup_length, tvbuf:range(0,2))
  tree:add(pup_transport, tvbuf:range(2,1))
  tree:add(pup_type, tvbuf:range(3,1))
  tree:add(pup_id, tvbuf:range(4,4))
  local dest_port = tree:add(tvbuf(8,6),"Dest port: ")
  port.dissector(tvbuf(8,6):tvb(), pinfo, dest_port)
  dest_port:append_text(string.format("%o#%o#%o#", tvbuf:range(8,1):uint(), tvbuf:range(9,1):uint(), tvbuf:range(10,4):uint()))
  local src_port = tree:add(tvbuf(14,6),"Src port: ")
  port.dissector(tvbuf(14,6):tvb(), pinfo, src_port)
  src_port:append_text(string.format("%o#%o#%o#", tvbuf:range(14,1):uint(), tvbuf:range(15,1):uint(), tvbuf:range(16,4):uint()))

  local type = tvbuf(3,1):uint()
  if puptypes[type] ~= nil then
    pinfo.cols.protocol:set(puptypes[type])
  else
    pinfo.cols.protocol:set("PUP")
  end
  local datalen = tvbuf(0,2):uint() - 22
  local datalen2 = datalen + (datalen % 2) -- round up to word
  tree:add(pup_checksum, tvbuf:range(20+datalen2,2))
  DissectorTable.get("pup"):try(type, tvbuf(20,datalen):tvb(), pinfo, root)
end

-- PUP packets have Ethernet type 0x200
DissectorTable.get("xeth"):add(0x200, pup)

DissectorTable.new("pup", "pup", ftypes.UINT8)

-- Dissector for port field of PUP packet. Not a full protocol.
port = Proto("port", "Port")
local port_net = ProtoField.uint8 ("port.net", "Net",  base.OCT)
local port_host = ProtoField.uint8 ("port.host", "Host",  base.OCT)
local port_socket = ProtoField.uint32 ("port.socket", "Socket", base.OCT)
port.fields = { port_net, port_host, port_socket }
function port.dissector(tvbuf,pinfo,root)
  root:add(port_net, tvbuf:range(0,1))
  root:add(port_host, tvbuf:range(1,1))
  root:add(port_socket, tvbuf:range(2,4))
end

-- Dissector for PUP Abort packet
local abort = Proto("abort", "Abort")
function abort.dissector(tvbuf,pinfo,root)
  local tree = root:add(abort, tvbuf:range(0,pktlen))
  tree:add(tvbuf(0,2),"Abort code: " .. tvbuf(0,2):uint())
  tree:add(tvbuf(2),"Message: " .. tvbuf(2):string())
  pinfo.cols.info:set(tvbuf(2):string())
end
DissectorTable.get("pup"):add(9, abort)

-- Dissector for PUP Gateway Info Reply packet
-- http://xeroxalto.computerhistory.org/_cd8_/pup/.gatewayinformation.bravo!1.html
local gateway_info_reply = Proto("gateway_info_reply", "Gateway Information Reply")
function gateway_info_reply.dissector(tvbuf,pinfo,root)
  local tree = root:add(gateway_info_reply, tvbuf:range(0,pktlen))
  for i=0,tvbuf:len()-3,4 do
    local resp_tree = tree:add(tvbuf(i,4),"Response")
    resp_tree:add(tvbuf(i,1),"Target net: " .. tvbuf(i,1):uint())
    resp_tree:add(tvbuf(i+1,1),"Gateway net: " .. tvbuf(i+1,1):uint())
    resp_tree:add(tvbuf(i+2,1),"Gateway host: " .. tvbuf(i+2,1):uint())
    resp_tree:add(tvbuf(i+3,1),"Hop count: " .. tvbuf(i+3,1):uint())
    if i == 0 then
      pinfo.cols.info:set("Target net: " ..tvbuf(0,1):uint())
    end
  end
  if tvbuf:len() % 4 ~= 0 then
    pinfo.cols.info:set("Bad length")
  end
end
DissectorTable.get("pup"):add(129, gateway_info_reply)

-- Dissector for "Breath of Life" Ethernet boot packet.
-- A raw Ethernet packet, not a PUP packet
local bol = Proto("bol", "Breath of Life")
function bol.dissector(tvbuf,pinfo,root)
  local tree = root:add(pup, tvbuf:range(0,pktlen))
  tree:set_text("Packet")
  pinfo.cols.info:set("Breath of Life: " .. tvbuf:len() .. " bytes")
end
DissectorTable.get("xeth"):add(0x182, bol)

