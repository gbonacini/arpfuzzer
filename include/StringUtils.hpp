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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <exception>
#include <iostream>
#include <iomanip>
#include <vector>
#include <array>
#include <set>
#include <string>
#include <cstring>
#include <initializer_list>

#include <anyexcept.hpp>

namespace stringutils{

   std::string mergeStrings(std::initializer_list<const char*> list)   noexcept;

   constexpr size_t  MAC_ARRAY_LEN {6 };
   constexpr size_t  IP_ARRAY_LEN  {4 };
   using MacAddr=std::array<uint8_t, MAC_ARRAY_LEN>;
   using IpAddr=std::array<uint8_t, IP_ARRAY_LEN>;

   IpAddr    parseIp(const std::string& buffer)             anyexcept;
   void      parseIpCheckOnly(const std::string& buffer)    anyexcept;
   MacAddr   parseMAC(const std::string& buffer)            anyexcept;

   class  StringUtilsException final : public std::exception {
           public:
                   explicit    StringUtilsException(int errNum)                                     noexcept;
                   explicit    StringUtilsException(const std::string&  errString)                  noexcept;
                   explicit    StringUtilsException(std::string&& errString)                        noexcept;
                               StringUtilsException(int errNum, const std::string& errString)       noexcept;
                               StringUtilsException(int errNum, std::string&& errString)            noexcept;
                   const char* what(void)                                                     const noexcept override;
                   int         getErrorCode(void)                                             const noexcept;

           private:
                   std::string errorMessage;
                   int errorCode;
   };

   void      decodeB64(const auto& in, auto& out)                                                        anyexcept;
   void      encodeB64(const auto& in, auto& out)                                                        anyexcept;

   uint16_t  checksum(void *buff, size_t len)                                                            noexcept;
   uint8_t   genRnd(std::vector<uint8_t>* array, ptrdiff_t start)                                        anyexcept;

 }  // End namespace stringutils
