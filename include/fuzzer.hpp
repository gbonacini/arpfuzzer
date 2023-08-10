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

#include <anyexcept.hpp>
#include <configFile.hpp>
#include <arplib.hpp>

#include <exception>
#include <string>
#include <array>

namespace arpfuzzer {

    using SockaddrUn=struct sockaddr_un;
    using Sockaddr=struct sockaddr;

    class ArpFuzzer {
        protected:

            arplib::Arpsocket                     arpsocket;
            configFile::ConfigFile&               configFile;
            statictypes::MacAddr                  hdMAC {},
                                                  hsMAC {},
                                                  sMAC  {},
                                                  tMAC  {};
        public:

            ArpFuzzer(const std::string& iface, 
                      arplib::FilterMap&& filters, 
                      configFile::ConfigFile& cfile)                            anyexcept;
            ~ArpFuzzer(void)                                                    noexcept;

            void   init(void)                                                   anyexcept;
            void   sendMessage(void)                                            anyexcept;
            void   shutdown(void)                                               noexcept;
    };
    
    class ArpFuzzerScript {
        private:
            configFile::ConfigScript              configScript;
            arplib::ArpsocketScript               arpsocket;
            configFile::ConfigFile&               configFile;
            static configFile::ArpCtx             arpCtx;

            statictypes::MacAddr                  hdMAC {},
                                                  hsMAC {},
                                                  sMAC  {},
                                                  tMAC  {};
        public:

            ArpFuzzerScript(const std::string& iface, 
                      arplib::FilterMap&& filters, 
                      configFile::ConfigFile& cfile,
                      const std::string& script)                                anyexcept;
            ~ArpFuzzerScript(void)                                              noexcept;

            void   init(void)                                                   anyexcept;
            void   sendMessage(void)                                            anyexcept;
    };

    class ArpFuzzerReadOnly {
        private:
            configFile::ConfigFile&       configFile;
            arplib::ArpsocketReadOnly     arpsocket;
            
        public:

            ArpFuzzerReadOnly(const std::string& iface, 
                              arplib::FilterMap&& filters,
                              configFile::ConfigFile& cfile)                   anyexcept;

            ~ArpFuzzerReadOnly(void)                                           noexcept;

            void   init(void)                                                  anyexcept;
            void   shutdown(void)                                              noexcept;
    };
           
    class ArpFuzzerException final : public std::exception {
        public:
           ArpFuzzerException(std::string& errString);
           ArpFuzzerException(std::string&& errString);
           const char* what(void)                                    const     noexcept;
        private:
           std::string errorMessage;
    };

} // End namespace chatterminal