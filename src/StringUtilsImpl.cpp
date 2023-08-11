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

#include <random>

#include <StringUtils.hpp>

namespace stringutils{

  using std::string,
        std::stoul,
        std::mt19937,
        std::random_device,
        std::uniform_int_distribution,
        std::vector,
        std::initializer_list;

  string mergeStrings(initializer_list<const char*> list) noexcept{
       string buff {""};

       for( auto elem : list)
           buff.append(elem);

       return buff;
   }

   IpAddr  parseIp(const string& buffer) anyexcept {
        size_t        countDigits     { 0 },
                      countBlocks     { 0 },
                      pos             { 0 };
        unsigned long digit           { 0 };
        string        digitBuff       { "" };
        IpAddr        result;

        for(auto chr : buffer){
                switch(chr){
                    case '0':
                    case '1':
                    case '2':
                    case '3':
                    case '4':
                    case '5':
                    case '6':
                    case '7':
                    case '8':
                    case '9':
                                countDigits++;
                                if(countDigits > 3)
                                    throw StringUtilsException("stringutils::parseIp()- invalid data - digits");
                                digitBuff.push_back(chr);
                        break;
                    case '.':
                                countDigits = 0;
                                if(countBlocks + 1 > 3)
                                    throw StringUtilsException("stringutils::parseIp()- invalid data - separators");
                                digit = stoul(digitBuff.c_str(), &pos, 10);
                                if(digit > 255)
                                    throw StringUtilsException("stringutils::parseIp()- invalid data - value");
                                result.at(countBlocks) = digit;
                                digitBuff.clear();
                                countBlocks++;
                        break;

                    default:
                          throw StringUtilsException("stringutils::parseIp()- invalid data");
                }
        }
        if(digitBuff.empty())
               throw StringUtilsException("stringutils::parseIp()- invalid data");
        digit = stoul(digitBuff.c_str(), &pos, 10);
        if(digit > 255)
               throw StringUtilsException("stringutils::parseIp()- invalid data - value");
        result.at(countBlocks) = digit;

        return result;
   }

   void   parseIpCheckOnly(const string& buffer)    anyexcept{
        size_t        countDigits     { 0 },
                      countBlocks     { 0 },
                      pos             { 0 };
        unsigned long digit           { 0 };
        string        digitBuff       { "" };

        for(auto chr : buffer){
                switch(chr){
                    case '0':
                    case '1':
                    case '2':
                    case '3':
                    case '4':
                    case '5':
                    case '6':
                    case '7':
                    case '8':
                    case '9':
                                countDigits++;
                                if(countDigits > 3)
                                    throw StringUtilsException("stringutils::parseIp()- invalid data - digits");
                                digitBuff.push_back(chr);
                        break;
                    case '.':
                                countDigits = 0;
                                if(countBlocks + 1 > 3)
                                    throw StringUtilsException("stringutils::parseIp()- invalid data - separators");
                                digit = stoul(digitBuff.c_str(), &pos, 10);
                                if(digit > 255)
                                    throw StringUtilsException("stringutils::parseIp()- invalid data - value");
                                digitBuff.clear();
                                countBlocks++;
                        break;

                    default:
                          throw StringUtilsException("stringutils::parseIp()- invalid data");
                }
        }
        if(digitBuff.empty())
                throw StringUtilsException("stringutils::parseIp()- invalid data");
        digit = stoul(digitBuff.c_str(), &pos, 10);
        if(digit > 255)
                throw StringUtilsException("stringutils::parseIp()- invalid data - value");
   }

   MacAddr parseMAC(const string& buffer) anyexcept {
        size_t        countDigits     { 0 },
                      countBlocks     { 0 },
                      pos             { 0 };
        unsigned long digit           { 0 };
        string        digitBuff       { "" };
        MacAddr       result;

        for(auto chr : buffer){
                switch(chr){
                    case '0':
                    case '1':
                    case '2':
                    case '3':
                    case '4':
                    case '5':
                    case '6':
                    case '7':
                    case '8':
                    case '9':
                    case 'a':
                    case 'b':
                    case 'c':
                    case 'd':
                    case 'e':
                    case 'f':
                    case 'A':
                    case 'B':
                    case 'C':
                    case 'D':
                    case 'E':
                    case 'F':
                    case 'x':
                    case 'X':
                                countDigits++;
                                if(countDigits > 4)
                                    throw StringUtilsException("stringutils::parseMAC()- invalid data - digits");
                                digitBuff.push_back(chr);
                        break;
                    case ':':
                                countDigits = 0;
                                if(countBlocks + 1 > 5)
                                    throw StringUtilsException("stringutils::parseMAC()- invalid data - separators");
                                digit = stoul(digitBuff.c_str(), &pos, 16);
                                if(digit > 255)
                                    throw StringUtilsException("stringutils::parseMAC()- invalid data - value");
                                result.at(countBlocks) = digit;
                                digitBuff.clear();
                                countBlocks++;
                        break;

                    default:
                          throw StringUtilsException("stringutils::parseMAC()- invalid data");
                }
        }
        if(digitBuff.empty())
            throw StringUtilsException("stringutils::parseMAC()- invalid data");
        digit = stoul(digitBuff.c_str(), &pos, 16);
        if(digit > 255)
            throw StringUtilsException("stringutils::parseMAC()- invalid data - value");
        result.at(countBlocks) = digit;

        return result;
   }

  static const  char      convTable[]   {
                                 'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
                                 'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
                                 'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
                                 'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/'
  };

  static const  uint8_t   checkTable[]  {
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62, 255, 255, 255,   63,
                                  52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255, 255, 255, 255, 255,
                                 255,   0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
                                  15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255, 255,
                                 255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,
                                  41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
   };

   StringUtilsException::StringUtilsException(int errNum) noexcept
        :   errorMessage{"None"}, errorCode{errNum}
   {}

   StringUtilsException::StringUtilsException(const string& errString) noexcept
        :  errorMessage{errString}, errorCode{0}
   {}

   StringUtilsException::StringUtilsException(string&& errString) noexcept
        :  errorMessage{errString}, errorCode{0}
   {}

   StringUtilsException::StringUtilsException(int errNum, const string& errString) noexcept
        :  errorMessage{errString}, errorCode{errNum}
   {}

   StringUtilsException::StringUtilsException(int errNum, string&& errString) noexcept
        :  errorMessage{errString}, errorCode{errNum}
   {}

   const char* StringUtilsException::what(void)    const noexcept {
           return errorMessage.c_str();
   }

   int  StringUtilsException::getErrorCode(void)  const noexcept{
           return errorCode;
   }

  void decodeB64(const auto& in, auto& out) anyexcept{
         #ifdef __GNUC__
         #pragma GCC diagnostic push
         #pragma GCC diagnostic ignored "-Wtype-limits"
         #endif

         try{
            out.resize( [&in]() -> size_t { auto i{in.cbegin()}; auto j{i};
                                            for(; *i != 255 && i!= in.cend(); ++i);
                                            return ( ((static_cast<size_t>(i-j) + 2) / 4) * 3); }()
                       );
         }catch(...){
            throw StringUtilsException("decodeB64: Data error.");
         }

         #ifdef __GNUC__
         #pragma GCC diagnostic pop
         #endif

         auto i{in.cbegin()}; auto j{out.begin()};
         for(; i<in.cend()-4; i+=4, j+=3){
                 *j      = static_cast<uint8_t>(checkTable[static_cast<size_t>(*i)]     << 2 |
                           checkTable[static_cast<size_t>(*(i+1))] >> 4);
                 *(j+1)  = static_cast<uint8_t>(checkTable[static_cast<size_t>(*(i+1))] << 4 |
                           checkTable[static_cast<size_t>(*(i+2))] >> 2);
                 *(j+2)  = static_cast<uint8_t>(checkTable[static_cast<size_t>(*(i+2))] << 6 |
                           checkTable[static_cast<size_t>(*(i+3))]     );
         }

         if(i < (in.cend() - 1))
                 *j      = static_cast<uint8_t>(checkTable[static_cast<size_t>(*i)]     << 2 |
                           checkTable[static_cast<size_t>(*(i+1))] >> 4);
         if(i < (in.cend() - 2))
                 *(j+1)  = static_cast<uint8_t>(checkTable[static_cast<size_t>(*(i+1))] << 4 |
                           checkTable[static_cast<size_t>(*(i+2))] >> 2);
         if(i < (in.cend() - 3))
                 *(j+2)  = static_cast<uint8_t>(checkTable[static_cast<size_t>(*(i+2))] << 6 |
                           checkTable[static_cast<size_t>(*(i+3))]     );
  }

  void encodeB64(const auto& in, auto& out) anyexcept{
         try{
             out.resize((in.size() + 2) / 3 * 4);
         }catch(...){
            throw StringUtilsException("encodeB64: Data error.");
         }

          auto i{in.cbegin()}; auto j{out.begin()};
          for(; i<in.cend()-2; i+=3, j+=4){
                  *j     = convTable[(*i >> 2) & 0x3F];
                  *(j+1) = convTable[static_cast<size_t>(((*i     & 0x3) << 4) |
                                                             static_cast<int>(((*(i+1) & 0xF0) >> 4 )))];
                  *(j+2) = convTable[static_cast<size_t>(((*(i+1) & 0xF) << 2) |
                                                             static_cast<int>(((*(i+2) & 0xC0) >> 6 )))];
                  *(j+3) = convTable[  *(i+2) & 0x3F];
          }

          if(i < in.cend()){
                  *j     = convTable[(*i >> 2) & 0x3F];
                  if(i == (in.cend() -1)){
                          *(j+1) = convTable[static_cast<size_t>((*i  & 0x3) << 4)];
                          *(j+2) = '=';
                  }else{
                          *(j+1) = convTable[static_cast<size_t>((*i      & 0x3) << 4 |
                                                             static_cast<int>(((*(i+1) & 0xF0) >> 4 )))];
                          *(j+2) = convTable[static_cast<size_t>(((*(i+1) & 0xF) << 2))];
                  }
                  *(j+3) = '=';
          }
  }

  #ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wsign-compare"
  #pragma GCC diagnostic ignored "-Wtype-limits"
  #endif

  #if defined  __clang_major__ && __clang_major__ >= 4 && !defined __APPLE__ && __clang_major__ >= 4
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wundefined-func-template"
  #endif

  template void   encodeB64(const vector<uint8_t>& in, string& out)   anyexcept;
  template void   decodeB64(const string& in, vector<uint8_t>& out)   anyexcept;

  #ifdef __GNUC__
  #pragma GCC diagnostic pop
  #endif

  #if defined  __clang_major__ && __clang_major__ >= 4 && !defined __APPLE__ && __clang_major__ >= 4
  #pragma clang diagnostic pop
  #endif

  uint8_t genRnd(vector<uint8_t> *array, ptrdiff_t start) anyexcept{
        try{
            random_device              rdev;
            mt19937                    gen{rdev()};
            uniform_int_distribution<> dis(0, 255);

            if(array == nullptr){
                return static_cast<uint8_t>(dis(gen));
            }else{
                for(auto i = array->begin() + start; i != array->end(); ++i)
                    *i = static_cast<uint8_t>(dis(gen));
                return 0;
            }
        }catch(...){
            string errmsg { "genRnd: Error generating random numbers" };
            throw StringUtilsException(errmsg);
        }
    }

    uint16_t checksum(void *buff, size_t len) noexcept{
        uint16_t        odd_byte   { 0 },
                        *buffer    { static_cast<uint16_t*>(buff) };
        uint32_t        sum        { 0 };

        while(len > 1){
            sum += *buffer++;
            len -= 2;
        }

        if( len == 1 ){
            *(reinterpret_cast<uint8_t*>(&odd_byte)) = *(reinterpret_cast<uint8_t*>(buffer));
            sum += odd_byte;
        }

        sum =  ( sum >> 16 ) + ( sum & 0xffff );
        sum += ( sum >> 16 );
        return static_cast<uint16_t>(~sum);
    }

} // End namespace stringutils
