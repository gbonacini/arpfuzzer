--[[ Name:           Test1
     Synopsis:       Set 'prot type' ARP field to 6, then it will send 16 ARP packets with the MAC address
                     of the sender in the range '0F:00:11:22:33:44' - 'FF:00:11:22:33:44'
--]]

setProtType(6)

macChars = { '1','2','3','4','5','6','7','8','9','0','A','B','C','D','E','F' }
macSuffix = "F:00:11:22:33:44"

for idx=1, #macChars do
    sMac = macChars[idx] .. macSuffix    
    setSrcMAC(sMac)
    send()
end
