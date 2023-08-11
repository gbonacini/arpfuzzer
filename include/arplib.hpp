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

#pragma once

#include <time.h>

#include <netinet/ip.h>
#include <net/if.h>
#include <linux/if_packet.h>  // struct sockaddr_ll

#include <sys/un.h>
#include <sys/select.h>

#include <cstddef>
#include <exception>
#include <string>
#include <array>
#include <vector>
#include <queue>
#include <deque>
#include <map>
#include <tuple>
#include <functional>
#include <atomic>

#include <thread>
#include <mutex>

#include <StaticTypes.hpp>
#include <anyexcept.hpp>
#include <debug.hpp>

namespace arplib{

    constexpr size_t  MSG_LEN       {10};
    constexpr uint8_t MAX_ATTEMPTS  {3 };

    enum PACKET_MAPPING : size_t { IPHDR_DEST_MAC=0, IPHDR_SRC_MAC=6, FRAME_TYPE=12, HARD_TYPE=14, PROT_TYPE=16,
                                   HARD_SIZE=18, PROT_SIZE=19, OP_SIZE=20, SENDER_MAC=22, SENDER_IP=28,
                                   DEST_MAC=32, DEST_IP=38 };

    enum MSG_DATA_IDXS : size_t { PART_ID_IDX=0, EXPIRING_TIME_IDX=1, ATTEMPTS_IDX=2, MSG_DATA_IDX=3 };

    struct ArpPkt {
         uint8_t  hdrTargetMAC[statictypes::MAC_ARRAY_LEN],
                  hdrSenderMAC[statictypes::MAC_ARRAY_LEN];
         uint16_t frameType,
                  hardType,
                  protType;
         uint8_t  hardSize { 0x6 },
                  protSize { 0x4 };
         uint16_t opcode;
         uint8_t  senderMAC[statictypes::MAC_ARRAY_LEN],
                  senderIp[statictypes::IP_ARRAY_LEN],
                  targetMAC[statictypes::MAC_ARRAY_LEN],
                  targetIp[statictypes::IP_ARRAY_LEN];
    };

    using ArpBuffer=std::array<uint8_t, IP_MAXPACKET>;

    class ArpsocketBase {
        protected:
          using SockaddrLl=struct sockaddr_ll;

          std::string                 interface      { "" };
          int                         sfd            { -1 };
          ArpPkt                      arppkt         {};
          SockaddrLl                  sockaddrll     {};
          debugmode::DEBUG_MODE       debugLevel;
          ArpBuffer                   incoming;

        public:
          explicit ArpsocketBase(const std::string& iface)             noexcept;
          ~ArpsocketBase(void)                                         noexcept;

          void     open(void)                                          anyexcept;

          void     setSrcHdrMAC(const statictypes::MacAddr& shMAC)     noexcept;
          void     setDestHdrMAC(const statictypes::MacAddr& dhMAC)    noexcept;
          void     setAllDestMAC(const statictypes::MacAddr& dhMAC)    noexcept;
          void     setFrameType(uint16_t fr)                           noexcept;
          void     setHardType(uint16_t  ht)                           noexcept;
          void     setProtType(uint16_t  pt)                           noexcept;
          void     setHardSize(uint8_t   hs)                           noexcept;
          void     setProtSize(uint8_t   ps)                           noexcept;
          void     setOpcode(uint16_t    op)                           noexcept;
          void     setDestMAC(const statictypes::MacAddr& dMAC)        noexcept;
          void     setDestIp(const std::string& dIp)                   noexcept;
          void     setSrcMAC(const statictypes::MacAddr& sMAC)         noexcept;
          void     setSrcIp(const std::string& sIp)                    noexcept;

          void     getSrcHdrMAC(statictypes::MacAddr& dest)    const   noexcept;
          void     getDestHdrMAC(statictypes::MacAddr& dest)   const   noexcept;
          uint16_t getFrameType(void)                          const   noexcept;
          uint16_t getHardType(void)                           const   noexcept;
          uint16_t getProtType(void)                           const   noexcept;
          uint16_t getHardSize(void)                           const   noexcept;
          uint16_t getProtSize(void)                           const   noexcept;
          uint16_t getOpcode(void)                             const   noexcept;
          void     getDestMAC(statictypes::MacAddr& dest)      const   noexcept;
          void     getDestIp(std::string& dest)                const   noexcept;
          void     getSrcMAC(statictypes::MacAddr& dest)       const   noexcept;
          void     getSrcIp(std::string& dest)                 const   noexcept;
    };

    union FilterValue{
         uint8_t               bt;
         uint16_t              doublebt;
         statictypes::MacAddr  btarrMAC;
         statictypes::IpAddr   btarrIp;

         FilterValue(uint8_t val)                                      noexcept;
         FilterValue(uint16_t val)                                     noexcept;
         FilterValue(statictypes::MacAddr&& val)                       noexcept;
         FilterValue(statictypes::IpAddr&& val)                        noexcept;
    };

    using FilterMap=std::map<std::string, FilterValue>;

    class ArpsocketFiltered : public ArpsocketBase {
        protected:

           using FilterActions=std::map<std::string, std::function<bool(ArpPkt&, FilterValue&)>>;

           ArpPkt                     lastPacketRecv {};
           FilterMap                  filters;
           FilterActions              filterActions{
                  { "frameType",  [](ArpPkt& pck, FilterValue& ft)-> bool { return ft.doublebt == pck.frameType ? false : true;} },
                  { "hardType",   [](ArpPkt& pck, FilterValue& ft)-> bool { return ft.doublebt == pck.hardType ? false : true;} },
                  { "protType",   [](ArpPkt& pck, FilterValue& ft)-> bool { return ft.doublebt == pck.protType ? false : true;} },
                  { "hardSize",   [](ArpPkt& pck, FilterValue& ft)-> bool { return ft.bt == pck.hardSize  ? false : true;} },
                  { "protSize",   [](ArpPkt& pck, FilterValue& ft)-> bool { return ft.bt == pck.protSize ? false : true;} },
                  { "opcode",     [](ArpPkt& pck, FilterValue& ft)-> bool { return ft.doublebt == pck.opcode  ? false : true;} },
                  { "senderMAC",  [](ArpPkt& pck, FilterValue& ft)-> bool { for(size_t el=0; el< sizeof(pck.senderMAC); el++)
                                                                            if(ft.btarrMAC.at(el) != pck.senderMAC[el]) return true; return false;} },
                  { "senderIp",   [](ArpPkt& pck, FilterValue& ft)-> bool { for(size_t el=0; el< sizeof(pck.senderIp); el++)
                                                                            if(ft.btarrIp.at(el) != pck.senderIp[el]) return true; return false;} },
                  { "targetMAC",  [](ArpPkt& pck, FilterValue& ft)-> bool { for(size_t el=0; el< sizeof(pck.targetMAC); el++)
                                                                            if(ft.btarrMAC.at(el) != pck.targetMAC[el]) return true; return false;} },
                  { "targetIp",   [](ArpPkt& pck, FilterValue& ft)-> bool { for(size_t el=0; el< sizeof(pck.senderIp); el++)
                                                                            if(ft.btarrIp.at(el) != pck.senderIp[el]) return true; return false;} }
            };

        public:
           ArpsocketFiltered(const std::string& iface,
                             FilterMap&& filt)                          noexcept;

           inline bool applyFilters(void)                               anyexcept;
    };

    class Arpsocket : public ArpsocketFiltered {

        protected:

           using Ifreq=struct ifreq;
           using SockaddrIn=struct sockaddr_in;
           using SockaddrUn=struct sockaddr_un;
           using Sockaddr=struct sockaddr;
           using MsgId=size_t;
           using PartId=size_t;
           using ExpiringTime=time_t;
           using Attempts=uint8_t;
           using MsgData=std::map<PartId, std::array<uint8_t, MSG_LEN> >;
           using MsgQueue=std::map<MsgId, std::tuple<PartId, ExpiringTime, Attempts, MsgData> >;

           std::string                UDDevice       {"/tmp/.arpfuzzer.uddsocket.server"};
           int                        udsfd          { -1 },
                                      nfds           { -1 };
           Ifreq                      ifreq          {};
           SockaddrIn*                sockaddrin     { nullptr };
           SockaddrUn                 udsclient      {};
           ArpBuffer                  etherFrame;
           std::deque<ArpPkt>         incomingQueue;
           fd_set                     fdset;
           struct  timeval            tvMin          { 3,0 },
                                      tvMax          { 10,0 };
           std::thread                *reader        {nullptr};
           std::mutex                 queueMtx;
           MsgQueue                   received,
                                      sent;
           volatile std::atomic<bool> running        {true};

           void resolve(void)                                        anyexcept;
           void printSrcMAC(void)                             const  noexcept;
           void printDstMAC(void)                             const  noexcept;
           void printSrcIp(void)                              const  noexcept;

        public:

           Arpsocket(const std::string& iface,
                     FilterMap&& filt)                               noexcept;
           ~Arpsocket(void)                                          noexcept;

           void     init(void)                                       anyexcept;

           void     printConfig(void)                          const noexcept;
           int      send(void)                                       anyexcept;
           int      receive(bool dump=false)                         anyexcept;
           void     receiveAll(void)                                 noexcept;
           void     startReceiverThread(void)                        anyexcept;
           void     getLocalIp(void)                                 anyexcept;
           void     getLocalMAC(void)                                anyexcept;
           void     shutdown(void)                                   noexcept;
           ArpPkt   popPacket(void)                                  anyexcept;
           size_t   availeblePackets(void)                           noexcept;
    };

    class ArpsocketScript : public ArpsocketFiltered {
       using FilterActions=std::map<std::string, std::function<bool(ArpPkt&, FilterValue&)>>;

       private:
           ArpBuffer                  etherFrame;

       public:

           ArpsocketScript(const std::string& iface,
                           FilterMap&& filt)                          noexcept;
           ~ArpsocketScript(void)                                     noexcept;

           void     open(void)                                        anyexcept;
           int      send(void)                                        anyexcept;
    };

    class ArpsocketReadOnly : public Arpsocket {

      // deleted:
           void     setSrcHdrMAC(const statictypes::MacAddr& shMAC)             = delete;
           void     setDestHdrMAC(const statictypes::MacAddr& dhMAC)            = delete;
           void     setAllDestMAC(const statictypes::MacAddr& dhMAC)            = delete;
           void     setFrameType(uint16_t fr)                                   = delete;
           void     setHardType(uint16_t  ht)                                   = delete;
           void     setProtType(uint16_t  pt)                                   = delete;
           void     setHardSize(uint8_t   hs)                                   = delete;
           void     setProtSize(uint8_t   ps)                                   = delete;
           void     setOpcode(uint16_t    op)                                   = delete;
           void     setDestMAC(const statictypes::MacAddr& dMAC)                = delete;
           void     setDestIp(const std::string& dIp)                           = delete;
           void     setSrcMAC(const statictypes::MacAddr& sMAC)                 = delete;
           void     setSrcIp(const std::string& sIp)                            = delete;

           int      send(void)                                                  = delete;

           ArpPkt   popPacket(void)                                             = delete;
           size_t   availeblePackets(void)                                      = delete;

      public:

           ArpsocketReadOnly(const std::string& iface,
                             FilterMap&& filt)                     noexcept;
           ~ArpsocketReadOnly(void)                                noexcept;

           void     receiveAll(void)                               noexcept;
           void     startReceiverThread(void)                      anyexcept;
    };

    class ArpSocketException final : public std::exception {
        public:
           ArpSocketException(std::string& errString)              noexcept;
           ArpSocketException(std::string&& errString)             noexcept;
           const char* what(void)                        const     noexcept;
        private:
           std::string errorMessage;
    };

} // End namespace arplib

