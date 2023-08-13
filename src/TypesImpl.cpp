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

#include <Types.hpp>

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wtype-limits"
#endif

#if defined  __clang_major__ && __clang_major__ >= 4 && !defined __APPLE__ && __clang_major__ >= 4
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wundefined-func-template"
#endif

namespace typeutils{

  using std::string;

  TypesUtilsException::TypesUtilsException(int errNum) :
                       errorMessage("None"), errorCode(errNum)
  {}

  TypesUtilsException::TypesUtilsException(string errString) :
                       errorMessage(errString), errorCode(0)
  {}

  TypesUtilsException::TypesUtilsException(int errNum, string errString) :
                       errorMessage(errString), errorCode(errNum)
  {}

  const char* TypesUtilsException::what() const noexcept{
      return errorMessage.c_str();
  }

  int  TypesUtilsException::getErrorCode(void)  const noexcept{
      return errorCode;
  }

  template uint8_t         safeUint8(long long size)           anyexcept;
  template uint16_t        safeUint16(long long size)          anyexcept;

} // End namespace typeutils

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

#if defined  __clang_major__ && __clang_major__ >= 4 && !defined __APPLE__ && __clang_major__ >= 4
#pragma clang diagnostic pop
#endif
