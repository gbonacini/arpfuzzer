// -----------------------------------------------------------------
// arplib - a library to send arbitrary ARP packets
// Copyright (C) 2023  Gabriele Bonacini
//
// This program is distributed under dual license:
// - Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0) License
// for non commercial use, the license has the following terms:
// * Attribution — You must give appropriate credit, provide a link to the license,
// and indicate if changes were made. You may do so in any reasonable manner,
// but not in any way that suggests the licensor endorses you or your use.
// * NonCommercial — You must not use the material for commercial purposes.
// A copy of the license it's available to the following address:
// http://creativecommons.org/licenses/by-nc/4.0/
// - For commercial use a specific license is available contacting the author.
// -----------------------------------------------------------------

#include <errno.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/prctl.h>

#include <sstream>
#include <cstring>
#include <algorithm>
#include <cstdio>
#include <utility>

#include <debug.hpp>
#include <StringUtils.hpp>

#include <arplib.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if_arp.h>

#include <linux/if_ether.h>   // ETH_P_ARP = 0x0806
#include <linux/if.h>

namespace arplib{

    using std::copy,
          std::array,
          std::stringstream,
          std::string,
          std::to_string,
          std::setfill,
          std::setw,
          std::hex,
          std::dec,
          std::vector,
          std::tuple_size,
          std::thread,
          std::memcpy,
          std::terminate,
          debugmode::DEBUG_MODE,
          debugmode::Debug,
          stringutils::mergeStrings,
          statictypes::MacAddr,
          statictypes::IpAddr,
          statictypes::MAC_ARRAY_LEN,
          statictypes::IP_ARRAY_LEN;

    FilterValue::FilterValue(uint8_t val)   noexcept
         : bt{val}
    {}

    FilterValue::FilterValue(uint16_t val) noexcept
         : doublebt{val}
    {}

    FilterValue::FilterValue(MacAddr&& val) noexcept
         : btarrMAC{val}
    {}

    FilterValue::FilterValue(IpAddr&& val) noexcept
         : btarrIp{val}
    {}

    ArpsocketBase::ArpsocketBase(const string& iface) noexcept
            : interface{iface},
              debugLevel{Debug::getDebugLevel()}
    {
        sockaddrll.sll_family = AF_PACKET;
        sockaddrll.sll_halen = htons(6);
    }

    ArpsocketBase::~ArpsocketBase(void) noexcept{
        if(sfd != -1) close(sfd);
    }

    void ArpsocketBase::open(void) anyexcept{
         if((sfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
            string errmsg = mergeStrings({"Error: socket() : ", strerror(errno)});
            Debug::printLog(errmsg, debugLevel);
            throw ArpSocketException(errmsg);
         }
    }

    void ArpsocketBase::setAllDestMAC(const MacAddr& dhMAC) noexcept{
         setDestHdrMAC(dhMAC);
         setDestMAC(dhMAC);
    }

    void ArpsocketBase::setDestHdrMAC(const MacAddr& dhMAC) noexcept{
        static_assert( sizeof(arppkt.hdrTargetMAC) == MAC_ARRAY_LEN);
        copy(dhMAC.begin(), dhMAC.begin() + sizeof(arppkt.hdrTargetMAC), arppkt.hdrTargetMAC);
    }

    void ArpsocketBase::setSrcHdrMAC(const MacAddr& shMAC) noexcept{
        static_assert( sizeof(arppkt.hdrTargetMAC) == MAC_ARRAY_LEN);
        copy(shMAC.begin(), shMAC.begin() + sizeof(arppkt.hdrSenderMAC), arppkt.hdrSenderMAC);
    }

    void ArpsocketBase::setFrameType(uint16_t fr)  noexcept{
        arppkt.frameType = htons(fr);
    }

    void ArpsocketBase::setHardType(uint16_t  ht)  noexcept{
        arppkt.hardType = htons(ht);
    }

    void ArpsocketBase::setProtType(uint16_t  pt)  noexcept{
        arppkt.protType =  htons(pt);
    }

    void ArpsocketBase::setHardSize(uint8_t   hs)  noexcept{
        arppkt.hardSize = hs;
    }

    void ArpsocketBase::setProtSize(uint8_t   ps)  noexcept{
        arppkt.protSize = ps;
    }

    void ArpsocketBase::setOpcode(uint16_t    op)  noexcept{
        arppkt.opcode = htons(op);
    }

    void ArpsocketBase::setDestMAC(const MacAddr& dMAC) noexcept{
        static_assert( sizeof(arppkt.targetMAC) == MAC_ARRAY_LEN);
        copy(dMAC.begin(), dMAC.begin() + sizeof(arppkt.targetMAC), arppkt.targetMAC);
    }

    void ArpsocketBase::setDestIp(const string& dIp)  noexcept{
         inet_pton(AF_INET, dIp.c_str(), arppkt.targetIp);
    }

    void ArpsocketBase::setSrcMAC(const MacAddr& sMAC) noexcept{
        static_assert( sizeof(arppkt.senderMAC) == MAC_ARRAY_LEN);
        copy(sMAC.begin(), sMAC.begin() + sizeof(arppkt.senderMAC), arppkt.senderMAC);
    }

    void ArpsocketBase::setSrcIp(const string& sIp) noexcept{
        inet_pton(AF_INET, sIp.c_str(), arppkt.senderIp);
    }

    void ArpsocketBase::getSrcHdrMAC(MacAddr& dest)  const noexcept{
        copy(incoming.begin() + PACKET_MAPPING::IPHDR_SRC_MAC, incoming.begin() + PACKET_MAPPING::IPHDR_SRC_MAC + MAC_ARRAY_LEN, dest.data());
    }

    void ArpsocketBase::getDestHdrMAC(MacAddr& dest) const noexcept{
        copy(incoming.begin() + PACKET_MAPPING::IPHDR_DEST_MAC, incoming.begin() + PACKET_MAPPING::IPHDR_DEST_MAC + MAC_ARRAY_LEN, dest.data());
    }

    uint16_t ArpsocketBase::getFrameType(void) const noexcept{
        return *(reinterpret_cast<const uint16_t*>(incoming.data() + PACKET_MAPPING::FRAME_TYPE));
    }

    uint16_t ArpsocketBase::getHardType(void) const noexcept{
        return *(reinterpret_cast<const uint16_t*>(incoming.data() + PACKET_MAPPING::HARD_TYPE));
    }

    uint16_t ArpsocketBase::getProtType(void) const noexcept{
        return *(reinterpret_cast<const uint16_t*>(incoming.data() + PACKET_MAPPING::PROT_TYPE));
    }

    uint16_t ArpsocketBase::getHardSize(void) const noexcept{
        return *(reinterpret_cast<const uint16_t*>(incoming.data() + PACKET_MAPPING::HARD_SIZE));
    }

    uint16_t ArpsocketBase::getProtSize(void) const noexcept{
        return *(reinterpret_cast<const uint16_t*>(incoming.data() + PACKET_MAPPING::PROT_SIZE));
    }

    uint16_t ArpsocketBase::getOpcode(void) const noexcept{
        return *(reinterpret_cast<const uint16_t*>(incoming.data() + PACKET_MAPPING::OP_SIZE));
    }

    void ArpsocketBase::getDestMAC(MacAddr& dest)  const noexcept{
        copy(incoming.begin() + PACKET_MAPPING::DEST_MAC, incoming.begin() + PACKET_MAPPING::DEST_MAC + MAC_ARRAY_LEN, dest.data());
    }

    void ArpsocketBase::getDestIp(string& dest) const noexcept{
        dest.resize(IP_ARRAY_LEN);
        copy(incoming.begin() + PACKET_MAPPING::DEST_IP, incoming.begin() + PACKET_MAPPING::DEST_IP + IP_ARRAY_LEN, dest.data());
    }

    void ArpsocketBase::getSrcMAC(MacAddr& dest) const noexcept{
        copy(incoming.begin() + PACKET_MAPPING::SENDER_MAC, incoming.begin() + PACKET_MAPPING::SENDER_MAC + MAC_ARRAY_LEN, dest.data());
    }

    void ArpsocketBase::getSrcIp(string& dest) const noexcept{
        dest.resize(IP_ARRAY_LEN);
        copy(incoming.begin() + PACKET_MAPPING::SENDER_IP, incoming.begin() + PACKET_MAPPING::SENDER_IP + IP_ARRAY_LEN, dest.data());
    }

    ArpsocketFiltered::ArpsocketFiltered(const std::string& iface, FilterMap&& filt)  noexcept
       : ArpsocketBase(iface),
         filters{filt}
    {}

    bool ArpsocketFiltered::applyFilters(void) anyexcept{
        try{
            for(auto& [key, filter]: filters)
                 if( filterActions[key](lastPacketRecv, filter) )
                      return false;
        } catch(...){
            throw ArpSocketException("Error: applyFilters()");
        }

        return true;
    }

    Arpsocket::Arpsocket(const string& iface,  FilterMap&& filt) noexcept
        : ArpsocketFiltered(iface, move(filt))
    {
        // Default Frame Type (Request or Reply)
        arppkt.frameType = htons(0x0806);

        // Hard Type (0x1 -> Ethernet )
        arppkt.hardType = htons(1);

        // Protocol Type (IP Addresses ):
        arppkt.protType = htons(0x800);

        // OpCode (ARP request):
        arppkt.opcode = htons(0x1);

        inet_pton(AF_INET, "127.0.0.1", arppkt.targetIp);

        udsclient.sun_family = AF_UNIX;
    }

    void Arpsocket::init(void) anyexcept{
        copy(UDDevice.c_str(), UDDevice.c_str() + UDDevice.size(), udsclient.sun_path);

        resolve();

        if((sockaddrll.sll_ifindex = if_nametoindex (interface.c_str())) == 0) {
            string errmsg = mergeStrings({"Error: if_nametoindex() bad index : ", strerror(errno)});
            Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
            throw ArpSocketException(errmsg);
        }
    }

    Arpsocket::~Arpsocket(void) noexcept{
        shutdown();
        try{
            reader->join();
            delete reader;
        }catch(...){
            Debug::printLog("Error: Arpsocket dtor.", DEBUG_MODE::ERR_DEBUG);
        }
        if(udsfd != -1) close(udsfd);
    }

    void Arpsocket::printSrcMAC(void) const noexcept{
        stringstream msg;

        msg << "Src MAC: " ;
        for(const uint8_t& digit : arppkt.senderMAC)
                msg << " " << setfill('0') << setw(2) << hex << static_cast<int>(digit);

        msg << '\n' ;

        Debug::printLog(msg.str(), DEBUG_MODE::ERR_DEBUG);
    }

    void Arpsocket::printDstMAC(void) const noexcept{
        stringstream  msg;

        msg << "Dst MAC: " ;
        for(const uint8_t& digit : arppkt.targetMAC)
                msg << " " << setfill('0') << setw(2) << hex << static_cast<int>(digit);

        msg << '\n' ;

        Debug::printLog(msg.str(), DEBUG_MODE::ERR_DEBUG);
    }

    void Arpsocket::printSrcIp(void) const  noexcept{
        stringstream msg;

        msg << "Local IP: " ;
        for(const uint8_t& digit : arppkt.senderIp)
                msg << " " << dec << static_cast<int>(digit);

        msg << '\n' ;
        Debug::printLog(msg.str(), DEBUG_MODE::ERR_DEBUG);
    }

    void Arpsocket::printConfig(void) const noexcept{
         printSrcMAC();
         printDstMAC();
         printSrcIp();

         stringstream msg;
         msg << "ArpPkt size: " << sizeof(ArpPkt) << '\n' ;
         Debug::printLog(msg.str(), DEBUG_MODE::ERR_DEBUG);
    }

    int Arpsocket::send(void) anyexcept{
        static_assert( sizeof(arppkt) <= tuple_size<decltype(etherFrame)>{} );
        memcpy(etherFrame.data(), &arppkt, sizeof(arppkt));

        int bytesSent = sendto(sfd, etherFrame.data(), sizeof(ArpPkt), 0, reinterpret_cast<Sockaddr*>(&sockaddrll), sizeof (sockaddrll));
        if (bytesSent  <= 0){
             string errmsg = mergeStrings({"Error: sendto() : ", strerror(errno)});
             Debug::printLog(errmsg, debugLevel);
             throw ArpSocketException(errmsg);
        }

        if(debugLevel >= DEBUG_MODE::VERBOSE_DEBUG) Debug::trace("Sent:", etherFrame.data(), sizeof(ArpPkt), 0, 14);

        return bytesSent;
    }

    void Arpsocket::receiveAll(void) noexcept{

        try{
            string errmsg {""};

            udsfd = socket(AF_UNIX, SOCK_STREAM, 0);
            if(udsfd == -1){
                errmsg = mergeStrings({"Error: can't create UDS : ", strerror(errno)});
                Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
                throw ArpSocketException(errmsg);
            }

            int udsret { -1 },
                retry  {  5 };
            while(retry != 0){
                 udsret = connect(udsfd, reinterpret_cast<const Sockaddr*>(&udsclient), sizeof(SockaddrUn));
                 if(udsret != -1) break;
                 retry--;
                 usleep(1000);
            }
            if(udsret == -1){
                errmsg = mergeStrings({"Error: can't connect UDS : ", strerror(errno)});
                Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
                throw ArpSocketException(errmsg);
            }

            while(running){
                    FD_ZERO(&fdset);
                    FD_SET(sfd, &fdset);

                    if(sfd > nfds)
                        nfds = sfd + 1;

                    switch(ssize_t ret {::select(nfds, &fdset, nullptr, nullptr, &tvMin)}){
                        case -1:
                            errmsg = "readLineTimeout: Select Error.";
                            Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
                            throw ArpSocketException(errmsg);
                        case  0:
                            Debug::printLog("Select Timeout.", DEBUG_MODE::VERBOSE_DEBUG);
                            break;
                        default:
                            try{
                                ret = receive();
                            } catch (ArpSocketException& err){
                                    errmsg = mergeStrings({"Error: receiveAll() from receive() : ", err.what()});
                                    Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
                                    throw ArpSocketException(errmsg);
                            }
                            switch(ret){
                                case -2:
                                    Debug::printLog("All packed filtered with provided rule(s).", DEBUG_MODE::VERBOSE_DEBUG);
                                    break;
                                case -1:
                                    errmsg = mergeStrings({"Error: recvfrom() : ", strerror(errno)});
                                    Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
                                    throw ArpSocketException(errmsg);
                                case 0:
                                    errmsg = "readTimeout: Connection Closed by peer.";
                                    Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
                                    throw ArpSocketException(errmsg);
                                default:
                                        Debug::printLog("Packet Received.", DEBUG_MODE::VERBOSE_DEBUG);
                                        queueMtx.lock();
                                        string buf { to_string(incomingQueue.size()) };
                                        udsret = write(udsfd, buf.c_str(), buf.size());
                                        queueMtx.unlock();
                                        if(udsret == -1){
                                             errmsg = mergeStrings({"Error: can't write on UDS : ", strerror(errno)});
                                             Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
                                             throw ArpSocketException(errmsg);
                                        }
                            }
                    }
                    usleep(250);
            }
        } catch(ArpSocketException& err){
            Debug::printLog(mergeStrings({"Error in receiveAll() thread : ", err.what()}), DEBUG_MODE::ERR_DEBUG);
        } catch(...){
            Debug::printLog("Unhandled Exception in receiveAll().", DEBUG_MODE::ERR_DEBUG);
        }

        running = false;
    }

    void Arpsocket::startReceiverThread(void)  anyexcept{
          try{
              reader = new thread([&](){ receiveAll(); } );
          }catch (...){
                string msg {"Error: startReceiverThread() - creation "};
                Debug::printLog(msg, DEBUG_MODE::ERR_DEBUG);
                throw ArpSocketException(msg);
          }
    }

    int Arpsocket::receive(bool dump)  anyexcept{
        SockaddrIn cliaddr {};
        socklen_t clilen { sizeof(cliaddr) };

        static_assert( sizeof(ArpPkt) <= tuple_size<decltype(incoming)>{} );
        incoming = {};
        int bytesRecv = recvfrom(sfd, incoming.data(), incoming.size(), 0, reinterpret_cast<Sockaddr*>(&cliaddr), &clilen);
        if(bytesRecv == -1 ) return bytesRecv;

        memcpy(&lastPacketRecv, incoming.data(), sizeof(ArpPkt)) ;

        if(!applyFilters()) return -2;

        queueMtx.lock();
        incomingQueue.push_back(lastPacketRecv);
        queueMtx.unlock();

        if(dump){
            Debug::traceStdout("", incoming.data(), sizeof(ArpPkt), 0, 14);
        }else{
            if(debugLevel >= DEBUG_MODE::VERBOSE_DEBUG) Debug::trace("Received:", incoming.data(), sizeof(ArpPkt), 0, 14);
        }

        return bytesRecv;
    }

    ArpPkt Arpsocket::popPacket(void) anyexcept{
         queueMtx.lock();

         if(incomingQueue.empty()){
            queueMtx.unlock();
            string errmsg { "Error: attempt to pop from empty queue" };
            Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
            throw ArpSocketException(errmsg);
         }

         ArpPkt ret { incomingQueue.front() };
         incomingQueue.pop_front();
         queueMtx.unlock();
         return ret;
    }

    size_t Arpsocket::availeblePackets(void) noexcept{
        queueMtx.lock();
        size_t len { incomingQueue.size() };
        queueMtx.unlock();
        return len;
    }

    void Arpsocket::getLocalIp(void) anyexcept {
         int tempFd { socket(AF_INET, SOCK_DGRAM, 0) };
         if(tempFd == -1){
            string errmsg { mergeStrings({"getLocalIp: Error opening socket: ", strerror(errno)}) };
            Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
            throw ArpSocketException(errmsg);
         }

         ifreq.ifr_addr.sa_family = AF_INET;
         strncpy(ifreq.ifr_name, interface.c_str(), IFNAMSIZ-1);

         if(ioctl(tempFd, SIOCGIFADDR, &ifreq) == -1){
            string errmsg { mergeStrings({"getLocalIp: Error setting socket: ", strerror(errno)}) };
            Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
            throw ArpSocketException(errmsg);
         }

         sockaddrin=reinterpret_cast<SockaddrIn *>(&ifreq.ifr_addr);

         close(tempFd);
    }

    void Arpsocket::getLocalMAC(void) anyexcept {
        int tempFd { socket(AF_INET, SOCK_DGRAM, 0) };
        if(tempFd == -1){
            string errmsg { mergeStrings({"getLocalMAC: Error opening socket: ", strerror(errno)})};
            Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
            throw ArpSocketException(errmsg);
        }

        snprintf (ifreq.ifr_name, sizeof (ifreq.ifr_name), "%s", interface.c_str());
        if(ioctl (tempFd , SIOCGIFHWADDR, &ifreq) < 0){
            string errmsg { mergeStrings({"Error: ioctl() can't read source MAC address : ", strerror(errno)}) };
            Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
            throw ArpSocketException(errmsg);
        }

        close(tempFd);
    }

    void Arpsocket::resolve(void)  anyexcept {
        getLocalIp();
        static_assert( sizeof(reinterpret_cast<uint8_t*>(&sockaddrin->sin_addr)) >= sizeof(arppkt.senderIp));
        copy(reinterpret_cast<uint8_t*>(&sockaddrin->sin_addr), reinterpret_cast<uint8_t*>(&sockaddrin->sin_addr) + sizeof(arppkt.senderIp) , arppkt.senderIp);

        getLocalMAC();
        static_assert( sizeof(ifreq.ifr_hwaddr.sa_data) >= sizeof(arppkt.senderMAC));
        copy(ifreq.ifr_hwaddr.sa_data, ifreq.ifr_hwaddr.sa_data + sizeof(arppkt.senderMAC), arppkt.senderMAC);

        static_assert( sizeof(arppkt.hdrSenderMAC) == sizeof(arppkt.hdrSenderMAC));
        copy(arppkt.senderMAC, arppkt.senderMAC + sizeof(arppkt.hdrSenderMAC), arppkt.hdrSenderMAC);

        static_assert( sizeof(sockaddrll.sll_addr) >= sizeof(arppkt.senderMAC));
        copy(arppkt.senderMAC, arppkt.senderMAC + sizeof(arppkt.senderMAC), sockaddrll.sll_addr);
    }

    ArpSocketException::ArpSocketException(string& errString) noexcept
        : errorMessage{errString}
    {}

    ArpSocketException::ArpSocketException(string&& errString) noexcept
        : errorMessage{errString}
    {}

    const char*  ArpSocketException::what() const noexcept{
       return errorMessage.c_str();
    }

    void Arpsocket::shutdown(void)  noexcept{
         running = false;
    }

    ArpsocketReadOnly::ArpsocketReadOnly(const string& iface,  FilterMap&& filt) noexcept
        : Arpsocket(iface, move(filt))
    {}

    ArpsocketReadOnly::~ArpsocketReadOnly(void) noexcept
    {}

    void ArpsocketReadOnly::startReceiverThread(void)  anyexcept{
          try{
              reader = new thread([&](){ receiveAll(); } );
          }catch (...){
                string msg {"Error: startReceiverThread() - creation "};
                Debug::printLog(msg, DEBUG_MODE::ERR_DEBUG);
                throw ArpSocketException(msg);
          }
    }

    void ArpsocketReadOnly::receiveAll(void) noexcept{

        try{
            string errmsg {""};

            while(running){
                    FD_ZERO(&fdset);
                    FD_SET(sfd, &fdset);

                    if(sfd > nfds) nfds = sfd + 1;

                    switch( ssize_t ret {::select(nfds, &fdset, nullptr, nullptr, &tvMin)}){
                        case -1:
                            errmsg = "readLineTimeout: Select Error.";
                            Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
                            throw ArpSocketException(errmsg);
                        case  0:
                            Debug::printLog("Select Timeout.", DEBUG_MODE::VERBOSE_DEBUG);
                            break;
                        default:
                            try{
                                ret = receive(true);
                            } catch (ArpSocketException& err){
                                    errmsg = mergeStrings({"Error: receiveAll() from receive() : ", err.what()});
                                    Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
                                    throw ArpSocketException(errmsg);
                            }
                            switch(ret){
                                case -2:
                                    Debug::printLog("All packed filtered with provided rule(s).", DEBUG_MODE::VERBOSE_DEBUG);
                                    break;
                                case -1:
                                    errmsg = mergeStrings({"Error: recvfrom() : ", strerror(errno)});
                                    Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
                                    throw ArpSocketException(errmsg);
                                case 0:
                                    errmsg = "readTimeout: Connection Closed by peer.";
                                    Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
                                    throw ArpSocketException(errmsg);
                                default:
                                     Debug::printLog("Packet Received.", DEBUG_MODE::VERBOSE_DEBUG);
                            }
                    }
                    usleep(250);
            }
        } catch(ArpSocketException& err){
            Debug::printLog(mergeStrings({"Error in receiveAll() thread : ", err.what()}), DEBUG_MODE::ERR_DEBUG);
        } catch(...){
            Debug::printLog("Unhandled Exception in receiveAll().", DEBUG_MODE::ERR_DEBUG);
        }

        running = false;
    }


     ArpsocketScript::ArpsocketScript(const string& iface, FilterMap&& filt) noexcept
        : ArpsocketFiltered(iface, move(filt))
     {
        sockaddrll.sll_family = AF_PACKET;
        sockaddrll.sll_halen = htons(6);
     }

     ArpsocketScript::~ArpsocketScript(void) noexcept
     {}

     void ArpsocketScript::open(void)   anyexcept{

         if((sockaddrll.sll_ifindex = if_nametoindex (interface.c_str())) == 0) {
             string errmsg = mergeStrings({"Error: if_nametoindex() bad index : ", strerror(errno)});
             Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
             throw ArpSocketException(errmsg);
         }

         ArpsocketBase::open();
     }

     int ArpsocketScript::send(void)    anyexcept{
        static_assert( sizeof(arppkt) <= tuple_size<decltype(etherFrame)>{} );
        memcpy(etherFrame.data(), &arppkt, sizeof(arppkt));

        int bytesSent = sendto(sfd, etherFrame.data(), sizeof(ArpPkt), 0, reinterpret_cast<Sockaddr *>(&sockaddrll), sizeof (sockaddrll));
        if (bytesSent  <= 0){
             string errmsg = mergeStrings({"Error: sendto() : ", strerror(errno)});
             Debug::printLog(errmsg, debugLevel);
             throw ArpSocketException(errmsg);
        }

        if(debugLevel >= DEBUG_MODE::VERBOSE_DEBUG) Debug::trace("Sent:", etherFrame.data(), sizeof(ArpPkt), 0, 14);

        return bytesSent;
     }

} // End namespace arplib

