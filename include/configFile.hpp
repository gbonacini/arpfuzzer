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

extern "C" {
    #include <lua.h>
    #include <lauxlib.h>
    #include <lualib.h>
}

#include <string>
#include <array>
#include <map>
#include <anyexcept.hpp>

#include <arplib.hpp>

namespace configFile {

    union ConfigData{
        std::string text;
        long        integer;
        double      floatingPoint;
        bool        boolean;

        explicit ConfigData(std::string&  txt)   noexcept;
        explicit ConfigData(std::string&&  txt)  noexcept;
        explicit ConfigData(const char* txt)     noexcept;
        explicit ConfigData(long num)            noexcept;
        explicit ConfigData(double fl)           noexcept;
        explicit ConfigData(bool bol)            noexcept;
        ~ConfigData(void);
    };

    enum DATA_TYPE : char { BOOLEAN='B', INTEGER='I', FLOATING_POINT='F', TEXT='T'};

    class ConfigVar {
        private:
            DATA_TYPE  type;
            ConfigData data;
            bool       empty    {true};
            bool       optional {false};

        public:
            explicit              ConfigVar(std::string&& txt)              noexcept;
            explicit              ConfigVar(std::string& txt)               noexcept;
            explicit              ConfigVar(const char* txt)                noexcept;
            explicit              ConfigVar(long num)                       noexcept;
            explicit              ConfigVar(double fl)                      noexcept;
            explicit              ConfigVar(bool   bl)                      noexcept;

            DATA_TYPE             getDataType(void)                   const noexcept;

            const std::string&    getText(void)                       const anyexcept;
            void                  getMAC(statictypes::MacAddr& dst)   const anyexcept;
            void                  getIp(statictypes::IpAddr& dst)     const anyexcept;
            double                getFloat(void)                      const anyexcept;
            long                  getInteger(void)                    const anyexcept;
            bool                  getBool(void)                       const anyexcept;

            void                  setText(const std::string& val)           anyexcept;
            void                  setText(const std::string&& val)          anyexcept;
            void                  setFloat(double val)                      anyexcept;
            void                  setInteger(long val)                      anyexcept;
            void                  setBool(bool val)                         anyexcept;

            void                  setEmpty(bool val)                        noexcept;
            void                  setOptional(bool val)                     noexcept;

            bool                  isNum(void)                         const noexcept;
            bool                  isFloat(void)                       const noexcept;
            bool                  isText(void)                        const noexcept;
            bool                  isBool(void)                        const noexcept;

            bool                  isEmpty(void)                       const noexcept;
            bool                  isOptional(void)                    const noexcept;
    };

    using ConfigEnv=std::map<std::string, ConfigVar>;

    class ConfigFile {
           protected:
               std::string configurationFile {""};
               lua_State   *luaState         {nullptr};
               ConfigEnv   configEnv;

               std::string    loadString(const std::string& key)         anyexcept;
               long           loadInteger(const std::string& key)        anyexcept;
               double         loadFloat(const std::string& key)          anyexcept;
               bool           loadBool(const std::string& key)           anyexcept;

           public:
               explicit ConfigFile(const std::string& configfile)        noexcept;
               ~ConfigFile(void)                                         noexcept;
               void     init(void)                                       anyexcept;
               void     cleanConfig(void)                                noexcept;

               void     addLoadableVariable(std::string&& name,
                                            std::string dt,
                                            bool optional=false)         anyexcept;
               void     addLoadableVariable(std::string&& name,
                                            const char* dt,
                                            bool optional=false)         anyexcept;
               void     addLoadableVariable(std::string&& name,
                                            long dt,
                                            bool optional=false)         anyexcept;
               void     addLoadableVariable(std::string&& name,
                                            double dt,
                                            bool optional=false)         anyexcept;
               void     addLoadableVariable(std::string&& name,
                                            bool dt,
                                            bool optional=false)         anyexcept;

               void     loadConfig(void)                                 anyexcept;

               const ConfigVar&
                        getConf(const std::string& key)                  anyexcept;

               ConfigVar&
                        setConf(const std::string& key)                  anyexcept;

    };

    class ConfigScript {
         private:
               lua_State*  luaStateScript         {nullptr};
               std::string scriptFile             {""};

         public:
               explicit ConfigScript(const std::string& script)          noexcept;
               ~ConfigScript(void)                                       noexcept;
               void     init(void)                                       anyexcept;
               void     loadConfig(void)                                 anyexcept;
               void     cleanConfig(void)                                noexcept;
    };

    class ConfigFileException final : public std::exception {
        public:
           ConfigFileException(std::string& errString);
           ConfigFileException(std::string&& errString);
           const char* what(void)                             const     noexcept  override;
        private:
           std::string errorMessage;
    };

    class ArpCtx{
        private:
            static inline arplib::ArpsocketScript* arpsocket  { nullptr };
            static inline ConfigFile*              configFile { nullptr };

        public:
            static void  init(arplib::ArpsocketScript* arpsck,
                                     ConfigFile*        cfile)                 noexcept;
            static  const arplib::ArpsocketScript*
                         getArpSckInstance(void)                               noexcept;
            static int   send(lua_State *L)                                    noexcept;
            static int   setSrcHdrMAC(lua_State *L)                            anyexcept;
            static int   setDestHdrMAC(lua_State *L)                           anyexcept;
            static int   setFrameType(lua_State *L)                            anyexcept;
            static int   setHardType(lua_State *L)                             anyexcept;
            static int   setProtType(lua_State *L)                             anyexcept;
            static int   setHardSize(lua_State *L)                             anyexcept;
            static int   setProtSize(lua_State *L)                             anyexcept;
            static int   setOpcode(lua_State *L)                               anyexcept;
            static int   setDestMAC(lua_State *L)                              anyexcept;
            static int   setDestIp(lua_State *L)                               anyexcept;
            static int   setSrcMAC(lua_State *L)                               anyexcept;
            static int   setSrcIp(lua_State *L)                                anyexcept;

        // disabled:
            ArpCtx(void)                                                       = delete;
            ArpCtx(const ArpCtx&)                                              = delete;
            ArpCtx(const ArpCtx&&)                                             = delete;
            ArpCtx& operator= (const ArpCtx)                                   = delete;

    };


} // End namespace configFile
