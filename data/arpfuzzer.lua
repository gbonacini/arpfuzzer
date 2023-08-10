--[[ Flag:           hdrSenderMAC
     Type:           string reprenenting uint8_t 6 element array 
     Synopsis:       Set value for sender MAC address in header
     Valid values:   --
--]]
hdrSenderMAC = "0xEE:0xA9:0x42:0x5D:0x4C:0xD2"

--[[ Flag:           hdrTargetMAC
     Type:           string reprenenting uint8_t 6 element array 
     Synopsis:       Set value for target MAC address in header
     Valid values:   --
--]]
hdrTargetMAC = "0xFF:0xFF:0xFF:0xFF:0xFF:0xFF"

--[[ Flag:           frameType
     Type:           uint16_t integer 
     Synopsis:       Set value for frame type
     Valid values:   --
--]]
frameType = 0x806

--[[ Flag:           hardType
     Type:           uint16_t integer 
     Synopsis:       Set value for hardware type
     Valid values:   --
--]]
hardType = 0x0

--[[ Flag:           protType
     Type:           uint16_t integer 
     Synopsis:       Set value for protocol type
     Valid values:   --
--]]
protType = 0x0

--[[ Flag:           hardSize
     Type:           uint8_t integer 
     Synopsis:       Set value for hardware size
     Valid values:   --
--]]
hardSize = 0x6

--[[ Flag:           protSize
     Type:           uint8_t integer 
     Synopsis:       Set value for protocol size
     Valid values:   --
--]]
protSize = 0x4

--[[ Flag:           opcode
     Type:           uint16_t integer 
     Synopsis:       Set value for opcode
     Valid values:   --
--]]
opcode = 0x1

--[[ Flag:           senderMAC
     Type:           string reprenenting uint8_t 6 element array 
     Synopsis:       Set value for sender MAC address
     Valid values:   --
--]]
senderMAC = "0xFF:0xFF:0xFF:0xFF:0xFF:0xFF"

--[[ Flag:           targetMAC
     Type:           string reprenenting uint8_t 6 element array 
     Synopsis:       Set value for targer MAC address
     Valid values:   --
--]]
targetMAC = "0xFF:0xFF:0xFF:0xFF:0xFF:0xFF"

--[[ Flag:           senderIp
     Type:           string reprenenting uint8_t 4 element array 
     Synopsis:       Set value for sender IP address
     Valid values:   --
--]]
senderIp = "192.168.64.31"


--[[ Flag:           targetIp
     Type:           string reprenenting uint8_t 4 element array 
     Synopsis:       Set value for targer IP address
     Valid values:   --
--]]
targetIp = "192.168.64.31"



--[[ Flag:           frameTypeFilter
     Type:           uint16_t integer 
     Synopsis:       Set a filter allowing only packets with this value as frame type
     Valid values:   --
--]]
frameTypeFilter = 0x806

--[[ Flag:           hardTypeFilter
     Type:           uint16_t integer 
     Synopsis:       Set a filter allowing only packets with this value as hard type
     Valid values:   --
--]]
-- hardTypeFilter = 0x0

--[[ Flag:           protTypeFilter
     Type:           uint16_t integer 
     Synopsis:       Set a filter allowing only packets with this value as protocol type
     Valid values:   --
--]]
-- protTypeFilter = 0x0

--[[ Flag:           hardSizeFilter
     Type:           uint8_t integer 
     Synopsis:       Set a filter allowing only packets with this value as hard size
     Valid values:   --
--]]
-- hardSizeFilter = 0x0

--[[ Flag:           protSizeFilter
     Type:           uint8_t integer 
     Synopsis:       Set a filter allowing only packets with this value as protocol size
     Valid values:   --
--]]
-- protSizeFilter = 0x0

--[[ Flag:           opcodeFilter
     Type:           uint16_t integer 
     Synopsis:       Set a filter allowing only packets with this value as opcode
     Valid values:   --
--]]
opcodeFilter = 0x1

--[[ Flag:           senderMACFilter
     Type:           string reprenenting uint8_t 6 element array 
     Synopsis:       Set a filter allowing only packets with this value as sender MAC address
     Valid values:   --
--]]
-- senderMACFilter = "0xEE:0xA9:0x42:0x5D:0x4C:0xD2"

--[[ Flag:           senderIpFilter
     Type:           string reprenenting uint8_t 4 element array 
     Synopsis:       Set a filter allowing only packets with this value as sender IP address
     Valid values:   --
--]]
senderIpFilter = "192.168.64.31"


--[[ Flag:           targetMACFilter
     Type:           string reprenenting uint8_t 6 element array 
     Synopsis:       Set a filter allowing only packets with this value as target MAC address
     Valid values:   --
--]]
-- targetMACFilter = "0x0:0x0:0x0:0x0:0x0:0x0"

--[[ Flag:           targetIpFilter
     Type:           string reprenenting uint8_t 4 element array 
     Synopsis:       Set a filter allowing only packets with this value as sender IP address
     Valid values:   --
--]]
-- targetIpFilter = "0.0.0.0"

