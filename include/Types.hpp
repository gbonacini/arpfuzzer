// -----------------------------------------------------------------
// Tssh - A ssh test client.
// Copyright (C) 2016-2023  Gabriele Bonacini
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software Foundation,
// Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
// -----------------------------------------------------------------

#pragma once

#include <sys/types.h>
#include <stdint.h>

#include <exception>
#include <limits>
#include <cstddef>
#include <string>

#include <anyexcept.hpp>

namespace typeutils{

   class  TypesUtilsException final : public std::exception {
           public:
                   explicit    TypesUtilsException(int errNum);
                   explicit    TypesUtilsException(std::string errString);
                               TypesUtilsException(int errNum, std::string errString);
                   const char* what(void)                                                     const noexcept override;
                   int         getErrorCode(void)                                             const noexcept;
              private:
                   std::string errorMessage;
                   int errorCode;
   };

   #ifdef __clang__
   #pragma clang diagnostic push
   #pragma clang diagnostic ignored "-Wsign-compare"
   #endif

   #ifdef __GNUC__
   #pragma GCC diagnostic push
   #pragma GCC diagnostic ignored "-Wsign-compare"
   #pragma GCC diagnostic ignored "-Wtype-limits"
   #endif

   ssize_t safeSsizeT(auto size)  anyexcept{
      if(size > std::numeric_limits<ssize_t>::max())
         throw TypesUtilsException("Invalid conversion to ssize_t: overflow.");
      return static_cast<ssize_t>(size);
   }

   int safeInt(auto size)  anyexcept{
      if(size > std::numeric_limits<int>::max())
         throw TypesUtilsException("Invalid conversion to int: overflow.");
      return static_cast<int>(size);
   }

   ptrdiff_t safePtrdiff(auto offset)  anyexcept{
      if(offset > std::numeric_limits<ptrdiff_t>::max())
         throw TypesUtilsException("Invalid conversion to ptrdiff_t: overflow.");
      return static_cast<ptrdiff_t>(offset);
   }

   size_t safeSizeT(auto size)  anyexcept{
      if(size < 0)
         throw TypesUtilsException("Invalid conversion to size_t: negative value.");
      if(size > std::numeric_limits<size_t>::max())
         throw TypesUtilsException("Invalid conversion to size_t: overflow.");
      return static_cast<size_t>(size);
   }

   uint8_t safeUint8(auto size)  anyexcept{
      if(size < 0)
         throw TypesUtilsException("Invalid conversion to uint8_t: negative value.");
      if(size > std::numeric_limits<uint8_t>::max())
         throw TypesUtilsException("Invalid conversion to uint8_t: overflow.");
      return static_cast<uint8_t>(size);
   }

   uint16_t safeUint16(auto size)  anyexcept{
      if(size < 0)
         throw TypesUtilsException("Invalid conversion to uint16_t: negative value.");
      if(size > std::numeric_limits<uint16_t>::max())
         throw TypesUtilsException("Invalid conversion to uint16_t: overflow.");
      return static_cast<uint16_t>(size);
   }

   unsigned int safeUInt(auto size)  anyexcept{
      if(size < 0)
         throw TypesUtilsException("Invalid conversion to unsigned int: negative value.");
      if(size > std::numeric_limits<unsigned int>::max())
         throw TypesUtilsException("Invalid conversion to unsigned int: overflow.");
      return static_cast<unsigned int>(size);
   }

   unsigned long safeULong(auto size)  anyexcept{
      if(size < 0)
         throw TypesUtilsException("Invalid conversion to unsigned long: negative value.");
      if(size > std::numeric_limits<unsigned long>::max())
         throw TypesUtilsException("Invalid conversion to unsigned long: overflow.");
      return static_cast<unsigned long>(size);
   }

   uint32_t safeUint32(auto size)  anyexcept{
      if(size < 0)
         throw TypesUtilsException("Invalid conversion to uint32_t: negative value.");
      if(size > std::numeric_limits<uint32_t>::max())
         throw TypesUtilsException("Invalid conversion to uint32_t: overflow.");
      return static_cast<uint32_t>(size);
   }

   #ifdef __clang__
   #pragma clang diagnostic pop
   #endif

   #ifdef __GNUC__
   #pragma GCC diagnostic pop
   #endif
} // End namespace typeutils
