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

#include <fuzzer.hpp>
#include <debug.hpp>
#include <StringUtils.hpp>
#include <Types.hpp>

namespace arpfuzzer{

    using std::string,
          std::move,
          arplib::ArpPkt,
          arplib::Arpsocket,
          arplib::ArpsocketReadOnly,
          arplib::ArpSocketException,
          arplib::FilterMap,
          statictypes::MacAddr,
          statictypes::IpAddr,
          configFile::ConfigFile,
          configFile::ConfigScript,
          configFile::ConfigFileException,
          configFile::ArpCtx,
          debugmode::Debug,
          debugmode::DEBUG_MODE,
          stringutils::mergeStrings;

    ArpFuzzer::ArpFuzzer(const string& iface, FilterMap&& filters, ConfigFile& cfile) anyexcept
       : arpsocket{iface, move(filters)},
         configFile{cfile}
    {}

    ArpFuzzer::~ArpFuzzer(void)  noexcept{
         shutdown();
    }

    void ArpFuzzer::sendMessage(void) anyexcept {
            arpsocket.send();
    }

    void ArpFuzzer::shutdown(void) noexcept {
         arpsocket.shutdown();
    }

    void ArpFuzzer::init(void) anyexcept {
         try{
             configFile.getConf("hdrTargetMAC").getMAC(hdMAC);
             configFile.getConf("hdrSenderMAC").getMAC(hsMAC);
             configFile.getConf("targetMAC").getMAC(tMAC);
             configFile.getConf("senderMAC").getMAC(sMAC);

             arpsocket.init();
             arpsocket.open();

             arpsocket.setDestHdrMAC(hdMAC);
             arpsocket.setSrcHdrMAC(hsMAC);
             arpsocket.setDestMAC(tMAC);
             arpsocket.setSrcMAC(sMAC);

             arpsocket.setDestIp(configFile.getConf("targetIp").getText());
             arpsocket.setSrcIp(configFile.getConf("senderIp").getText());

             arpsocket.setFrameType(static_cast<uint16_t>(configFile.getConf("frameType").getInteger()));
             arpsocket.setHardType(static_cast<uint16_t>(configFile.getConf("hardType").getInteger()));
             arpsocket.setProtType(static_cast<uint16_t>(configFile.getConf("protType").getInteger()));
             arpsocket.setHardSize(static_cast<uint16_t>(configFile.getConf("hardSize").getInteger()));
             arpsocket.setProtSize(static_cast<uint16_t>(configFile.getConf("protSize").getInteger()));
             arpsocket.setOpcode(static_cast<uint16_t>(configFile.getConf("opcode").getInteger()));

             arpsocket.startReceiverThread();

         }catch(const ArpSocketException& ex){
             arpsocket.shutdown();
             throw ArpFuzzerException{mergeStrings({"Error: ArpFuzzer init: ", ex.what()})};
         }catch(...){
             throw ArpFuzzerException{"Unmanaged Error from ArpSocket init(). Abort."};
         }
    }

    ArpFuzzerScript::ArpFuzzerScript(const string& iface, FilterMap&& filters, ConfigFile& cfile, const string& script) anyexcept
       : configScript{script},
         arpsocket(iface, move(filters)),
         configFile{cfile}
    {
         ArpCtx::init(&arpsocket, &configFile);
    }

    ArpFuzzerScript::~ArpFuzzerScript(void)  noexcept
    {}

    void ArpFuzzerScript::sendMessage(void) anyexcept {
          arpsocket.send();
    }

    void ArpFuzzerScript::init(void) anyexcept {
         try{
             configFile.getConf("hdrTargetMAC").getMAC(hdMAC);
             configFile.getConf("hdrSenderMAC").getMAC(hsMAC);
             configFile.getConf("targetMAC").getMAC(tMAC);
             configFile.getConf("senderMAC").getMAC(sMAC);

             arpsocket.open();

             arpsocket.setDestHdrMAC(hdMAC);
             arpsocket.setSrcHdrMAC(hsMAC);
             arpsocket.setDestMAC(tMAC);
             arpsocket.setSrcMAC(sMAC);

             arpsocket.setDestIp(configFile.getConf("targetIp").getText());
             arpsocket.setSrcIp(configFile.getConf("senderIp").getText());

             arpsocket.setFrameType(static_cast<uint16_t>(configFile.getConf("frameType").getInteger()));
             arpsocket.setHardType(static_cast<uint16_t>(configFile.getConf("hardType").getInteger()));
             arpsocket.setProtType(static_cast<uint16_t>(configFile.getConf("protType").getInteger()));
             arpsocket.setHardSize(static_cast<uint16_t>(configFile.getConf("hardSize").getInteger()));
             arpsocket.setProtSize(static_cast<uint16_t>(configFile.getConf("protSize").getInteger()));
             arpsocket.setOpcode(static_cast<uint16_t>(configFile.getConf("opcode").getInteger()));

             configScript.init();
             configScript.loadConfig();
         }catch(const ArpSocketException& ex){
             throw ArpFuzzerException{mergeStrings({"Error: ArpFuzzerScript init: ", ex.what()})};
         }catch(...){
             throw ArpFuzzerException{"Unmanaged Error from ArpSocket init(). Abort."};
         }
    }

    ArpFuzzerReadOnly::ArpFuzzerReadOnly(const string& iface, FilterMap&& filters, ConfigFile& cfile) anyexcept
       : configFile{cfile},
         arpsocket{iface, move(filters)}
    {}

    ArpFuzzerReadOnly::~ArpFuzzerReadOnly(void)  noexcept{
         shutdown();
    }

    void ArpFuzzerReadOnly::init(void) anyexcept {
             arpsocket.init();
             arpsocket.open();
             arpsocket.startReceiverThread();
    }

    void ArpFuzzerReadOnly::shutdown(void) noexcept {
         arpsocket.shutdown();
    }

    ArpFuzzerException::ArpFuzzerException(string& errString)
      : errorMessage{errString}
    {}

    ArpFuzzerException::ArpFuzzerException(string&& errString)
      : errorMessage{errString}
    {}

    const char* ArpFuzzerException::what(void)   const noexcept {
       return errorMessage.c_str();
    }

} // End namespace arpfuzzer
