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

#include <unistd.h>
#include <stdlib.h>

#include <string>
#include <iostream>
#include <atomic>
#include <csignal>
#include <memory>
#include <filesystem>

#include <parseCmdLine.hpp>
#include <capabilities.hpp>
#include <configFile.hpp>
#include <arplib.hpp>
#include <debug.hpp>
#include <fuzzer.hpp>
#include <StringUtils.hpp>

using namespace std;

using namespace arplib;
using namespace capabilities;
using namespace debugmode;
using namespace parcmdline;
using namespace configFile;
using namespace arpfuzzer;
using namespace arpfuzzer;
using namespace statictypes;
using namespace stringutils;

#ifdef __clang__
  void printInfo(char* cmd) __attribute__((noreturn));
#else
  [[ noreturn ]]
  void printInfo(char* cmd);
#endif

volatile atomic<bool> running { true };

void sigint_handler([[maybe_unused]] int signal){
    running = false;
}

int main(int argc, char** argv){
    const char       flags[]          { "hd:i:f:r:ps:l:" };
    DEBUG_MODE       debugMode        { DEBUG_MODE::ERR_DEBUG };
    string           iface            { "" },
                     configFileName   { "./arpfuzzer.lua" },
                     scriptFileName   { "./arpfuzzerscript.lua" },
                     logFile          { "./arpfuzzer.log.txt" };
    int              ret              { 0 };
    size_t           repeat           { 1 };
    bool             printAnsw        { false },
                     shellMode        { false };

    signal(SIGINT, sigint_handler);

    ParseCmdLine  pcl{argc, argv, flags};

    if(pcl.getErrorState()){
        cerr << mergeStrings({"Invalid  parameter or value", pcl.getErrorMsg().c_str()}) << '\n';
        printInfo(argv[0]);
    }

    if(pcl.isSet('h'))
        printInfo(argv[0]);

    if(pcl.isSet('p'))
        printAnsw = true;

    if(pcl.isSet('d')){
            switch( stoul(pcl.getValue('d')) ){
                case 0:
                    debugMode = DEBUG_MODE::ERR_DEBUG;
                   break;
                case 1:
                    debugMode = DEBUG_MODE::STD_DEBUG;
                   break;
                case 2:
                    debugMode = DEBUG_MODE::VERBOSE_DEBUG;
                   break;
                default:
                    debugMode = DEBUG_MODE::STD_DEBUG;
            }
    }

    if(!pcl.isSet('i') ){
        cerr << "-i flag is mandatory" << '\n';
        printInfo(argv[0]);
    }

    if(pcl.isSet('f') ){
        configFileName = pcl.getValue('f');
        if(! filesystem::exists(configFileName)){
            cerr << mergeStrings({"Invalid  configuration file: ", configFileName.c_str()}) << '\n';
            printInfo(argv[0]);
        }
    }

    if(pcl.isSet('l') )
        logFile = pcl.getValue('l');

    size_t  ncomp {0};
    if(pcl.isSet('r') ) ncomp++;
    if(pcl.isSet('p') ) ncomp++;
    if(pcl.isSet('s') ) ncomp++;
    if(ncomp > 1){
        cerr << "-r, -p and -s are mutually exclusive" << '\n';
        printInfo(argv[0]);
    }

    if(pcl.isSet('r')){
        repeat = stoul(pcl.getValue('r'));
        if(repeat < 2)
            printInfo(argv[0]);
    }

    if(pcl.isSet('s') ){
        shellMode  = true;
        scriptFileName = pcl.getValue('s');
        if(! filesystem::exists(scriptFileName)){
            cerr << mergeStrings({"Invalid  script file: ", scriptFileName.c_str()}) << '\n';
            printInfo(argv[0]);
        }
    }

    try{
          ConfigFile cfg(configFileName);
          try{
                  cfg.init();

                  cfg.addLoadableVariable("hdrSenderMAC", "");
                  cfg.addLoadableVariable("hdrTargetMAC", "");
                  cfg.addLoadableVariable("frameType", 0L);
                  cfg.addLoadableVariable("hardType", 0L);
                  cfg.addLoadableVariable("protType", 0L);
                  cfg.addLoadableVariable("hardSize", 0L);
                  cfg.addLoadableVariable("protSize", 0L);
                  cfg.addLoadableVariable("opcode", 0L);
                  cfg.addLoadableVariable("targetMAC", "");
                  cfg.addLoadableVariable("senderMAC", "");
                  cfg.addLoadableVariable("targetIp", "");
                  cfg.addLoadableVariable("senderIp", "");

                  cfg.addLoadableVariable("frameTypeFilter", 0L, true);
                  cfg.addLoadableVariable("hardTypeFilter",  0L, true);
                  cfg.addLoadableVariable("protTypeFilter",  0L, true);
                  cfg.addLoadableVariable("hardSizeFilter",  0L, true);
                  cfg.addLoadableVariable("protSizeFilter",  0L, true);
                  cfg.addLoadableVariable("opcodeFilter",    0L, true);
                  cfg.addLoadableVariable("senderMACFilter", "", true);
                  cfg.addLoadableVariable("senderIpFilter",  "", true);
                  cfg.addLoadableVariable("targetMACFilter", "", true);
                  cfg.addLoadableVariable("targetIpFilter",  "", true);

                  cfg.loadConfig();

          } catch(ConfigFileException& ex){
              ret = 1;
              cerr << mergeStrings({"Error loading configuration file: ", ex.what()}) << '\n';
              printInfo(argv[0]);
              throw string{"Abort."};
          }

         Debug debug{debugMode};
         try{
             debug.init(logFile);

         }catch(DebugException& ex){
             ret = 1;
             cerr << "Error: " << ex.what() << '\n';
             throw string{"Abort."};
         }

         Capability cpb;
         try{
             cpb.init(true);
             cpb.reducePriv("cap_net_raw+ep");
             cpb.getCredential();
             if(debugMode > 1) cpb.printStatus();
         }catch(const CapabilityException& ex){
             ret = 1;
             cerr << "Error: " << ex.what() << '\n';
             throw string{"Abort."};
         }catch(...){
             ret = 1;
             cerr << "Error: unandled exception in privilege management." << '\n';
             throw string{"Abort."};
         }

         FilterMap filterMap;
         if(!cfg.getConf("frameTypeFilter").isEmpty()) filterMap.emplace("frameType",  htons(static_cast<uint16_t>(cfg.getConf("frameTypeFilter").getInteger())));
         if(!cfg.getConf("hardTypeFilter").isEmpty())  filterMap.emplace("hardType",   htons(static_cast<uint16_t>(cfg.getConf("hardTypeFilter").getInteger())));
         if(!cfg.getConf("protTypeFilter").isEmpty())  filterMap.emplace("protType",   htons(static_cast<uint16_t>(cfg.getConf("protTypeFilter").getInteger())));
         if(!cfg.getConf("hardSizeFilter").isEmpty())  filterMap.emplace("hardSize",   htons(static_cast<uint16_t>(cfg.getConf("hardSizeFilter").getInteger())));
         if(!cfg.getConf("protSizeFilter").isEmpty())  filterMap.emplace("protSize",   htons(static_cast<uint16_t>(cfg.getConf("protSizeFilter").getInteger())));
         if(!cfg.getConf("opcodeFilter").isEmpty())    filterMap.emplace("opcode",     htons(static_cast<uint16_t>(cfg.getConf("opcodeFilter").getInteger())));
         if(!cfg.getConf("senderMACFilter").isEmpty()){
            MacAddr macAddr;
            cfg.getConf("senderMACFilter").getMAC(macAddr);
            filterMap.emplace("senderMAC",  move(macAddr));
         }
         if(!cfg.getConf("senderIpFilter").isEmpty()){
            IpAddr ipAddr;
            cfg.getConf("senderIpFilter").getIp(ipAddr);
            filterMap.emplace("senderIp", move(ipAddr));
         }
         if(!cfg.getConf("targetMACFilter").isEmpty()){
            MacAddr macAddr;
            cfg.getConf("targetMACFilter").getMAC(macAddr);
            filterMap.emplace("targetMAC", move(macAddr));
         }
         if(!cfg.getConf("targetIpFilter").isEmpty()){
            IpAddr ipAddr;
            cfg.getConf("targetIpFilter").getIp(ipAddr);
            filterMap.emplace("targetIp",   move(ipAddr));
         }

         try{
             if(shellMode){
                 ArpFuzzerScript fuzzer(pcl.getValue('i'), move(filterMap), cfg, scriptFileName);
                 fuzzer.init();
             } else if (printAnsw){
                 ArpFuzzerReadOnly fuzzer(pcl.getValue('i'), move(filterMap), cfg);
                 fuzzer.init();
                 while(running) sleep(10);
             }else{
                 ArpFuzzer fuzzer(pcl.getValue('i'), move(filterMap), cfg);
                 fuzzer.init();
                 for(size_t lp{0}; running && ( lp < repeat ); lp++)
                     fuzzer.sendMessage();
             }
         } catch (ArpFuzzerException& ex){
             ret = 1;
             cerr << "Error: " << ex.what() << '\n';
             throw string{"Abort."};
         }

    }catch(const string& ex){
        cerr << ex << '\n';
        cout << "Program exits with error(s): check log file.\n";
    }

    return ret;
}

void printInfo(char* cmd){
      cerr << cmd << " [-i<iface>] [-f <config_full_path>] [-d level] [-l logfile] [-r repeats]\n";
      cerr << " | [-i<iface>] [-f <config_full_path>] [-d level] [-l logfile] [-s script]\n";
      cerr << " | [-i<iface>] [-f <config_full_path>] [-d level] [-l logfile] [-p script]\n";
      cerr << " | [-h]\n\n";
      cerr << " -i  <iface>     Specifies the network interface\n";
      cerr << " -f  <full_path> Specifies the configuration file path\n";
      cerr << " -r  <repeats>   Specifies how many identical datagrams must be sent [ 2 or more ]\n";
      cerr << " -s  <full_path> Shell mode: specifies the script file path\n";
      cerr << " -p              Passive mode: print filtered ARP packets\n";
      cerr << " -d  <dbg_level> Set debug mode\n";
      cerr << " -l  <logfile>   Set custom log file\n";
      cerr << " -h              Print this synopsis\n";
      exit(EXIT_FAILURE);
}

