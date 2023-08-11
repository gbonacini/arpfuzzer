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

#include <cstddef>
#include <cstdint>
#include <array>

namespace statictypes{

    enum TYPES_LEN : size_t { MAC_ARRAY_LEN=6, IP_ARRAY_LEN=4};

    using MacAddr=std::array<uint8_t, MAC_ARRAY_LEN>;
    using IpAddr=std::array<uint8_t, IP_ARRAY_LEN>;


} // End namespace statictypes
