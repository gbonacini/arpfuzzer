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

#include <stdexcept>

#include <configFile.hpp>
#include <StringUtils.hpp>
#include <Types.hpp>

namespace configFile{

    using std::string,
          std::to_string,
          std::stoul,
          std::array,
          std::out_of_range,
          stringutils::mergeStrings,
          stringutils::parseMAC,
          stringutils::parseIp,
          stringutils::parseIpCheckOnly,
          stringutils::StringUtilsException,
          stringutils::MacAddr,
          arplib::Arpsocket,
          arplib::ArpsocketScript,
          typeutils::safeUint16,
          typeutils::safeUint8,
          typeutils::TypesUtilsException,
          statictypes::MacAddr,
          statictypes::IpAddr,
          statictypes::MAC_ARRAY_LEN,
          statictypes::IP_ARRAY_LEN;

    ConfigData::ConfigData(string&& txt)  noexcept
         : text{txt}
    {}

    ConfigData::ConfigData(string& txt)  noexcept
         : text{move(txt)}
    {}

    ConfigData::ConfigData(const char* txt)   noexcept
         : text{txt}
    {}

    ConfigData::ConfigData(long num)         noexcept
          : integer{num}
    {}

    ConfigData::ConfigData(double fl)        noexcept
           : floatingPoint{fl}
    {}

    ConfigData::ConfigData(bool bol)         noexcept
            : boolean{bol}
    {}

    ConfigData::~ConfigData(void){
    }

    ConfigVar::ConfigVar(string& txt) noexcept
          : type { DATA_TYPE::TEXT},
            data {move(txt)}
    {}

    ConfigVar::ConfigVar(string&& txt) noexcept
          : type { DATA_TYPE::TEXT},
            data {txt}
    {}

    ConfigVar::ConfigVar(const char* txt)  noexcept
          : type { DATA_TYPE::TEXT},
            data { txt }
    {}

    ConfigVar::ConfigVar(long num)  noexcept
          : type { DATA_TYPE::INTEGER},
            data { num }
    {}

    ConfigVar::ConfigVar(double fl) noexcept
          : type { DATA_TYPE::FLOATING_POINT},
            data { fl }
    {}

    ConfigVar::ConfigVar(bool   bl)  noexcept
          : type { DATA_TYPE::BOOLEAN},
            data { bl }
    {}

    DATA_TYPE  ConfigVar::getDataType(void) const noexcept{
          return type;
    }

    const string& ConfigVar::getText(void) const anyexcept{
        if(type == DATA_TYPE::TEXT)
            return data.text;

        throw ConfigFileException("ConfigVar::getText()- wrong type");
    }

     void ConfigVar::getIp(IpAddr& dst) const anyexcept{

        if(type == DATA_TYPE::TEXT){
            try{
                 dst = parseIp( data.text);
            }catch(StringUtilsException& ex){
                 throw ConfigFileException(mergeStrings({"ConfigVar::getIp()- wrong value : ", ex.what()}));
            }
        } else {
               throw ConfigFileException("ConfigVar::getIp()- wrong type");
        }

     }

     void ConfigVar::getMAC(MacAddr& dst) const anyexcept{
        if(type == DATA_TYPE::TEXT){
            try{
                dst = parseMAC(data.text);
            }catch(StringUtilsException& ex){
                throw ConfigFileException(mergeStrings({"ConfigVar::getMAC()- wrong value : ", ex.what()}));
            }

        } else {
            throw ConfigFileException("ConfigVar::getMAC()- wrong type");
        }
    }

    double ConfigVar::getFloat(void)  const anyexcept{
        if(type == DATA_TYPE::FLOATING_POINT)
            return data.floatingPoint;

        throw ConfigFileException("ConfigVar::getFloat()- wrong type");
    }

    long  ConfigVar::getInteger(void) const anyexcept{
        if(type == DATA_TYPE::INTEGER)
            return data.integer;

        throw ConfigFileException("ConfigVar::getInteger()- wrong type");
    }

    bool  ConfigVar::getBool(void) const anyexcept{
        if(type == DATA_TYPE::BOOLEAN)
            return data.boolean;

        throw ConfigFileException("ConfigVar::getBool()- wrong type");
    }

    void   ConfigVar::setText(const string&& val) anyexcept{
        if(type == DATA_TYPE::TEXT)
               data.text = val;
        else
               throw ConfigFileException(mergeStrings({"ConfigVar::setText()- wrong type", val.c_str()}));
    }

    void   ConfigVar::setFloat(double val) anyexcept{
        if(type == DATA_TYPE::FLOATING_POINT)
               data.floatingPoint = val;
        else
               throw ConfigFileException(mergeStrings({"ConfigVar::setFloat()- wrong type", to_string(val).c_str()}));
    }

    void   ConfigVar::setInteger(long val) anyexcept{
        if(type == DATA_TYPE::INTEGER)
               data.integer = val;
        else
               throw ConfigFileException(mergeStrings({"ConfigVar::setInteger()- wrong type", to_string(val).c_str()}));
    }

    void   ConfigVar::setBool(bool val) anyexcept{
        if(type == DATA_TYPE::BOOLEAN)
               data.boolean = val;
        else
               throw ConfigFileException(mergeStrings({"ConfigVar::setBool()- wrong type", to_string(val).c_str()}));
    }

     void  ConfigVar::setEmpty(bool val) noexcept{
         empty = val;
     }

     void  ConfigVar::setOptional(bool val) noexcept{
         optional = val;
     }

    bool ConfigVar::isNum(void) const noexcept{
        return type == DATA_TYPE::INTEGER ? true :false;
    }

    bool ConfigVar::isFloat(void) const noexcept{
        return type == DATA_TYPE::FLOATING_POINT ? true :false;
    }

    bool ConfigVar::isText(void) const noexcept{
        return type == DATA_TYPE::TEXT ? true :false;
    }

    bool ConfigVar::isBool(void) const noexcept{
        return type == DATA_TYPE::BOOLEAN ? true :false;
    }

    bool ConfigVar::isEmpty(void) const noexcept{
        return empty;
    }

    bool ConfigVar::isOptional(void) const noexcept{
        return optional;
    }

    ConfigFile::ConfigFile(const string& configFile)  noexcept
        : configurationFile { configFile}
    {}

    void ConfigFile::init(void)  anyexcept{
        luaState = luaL_newstate();
        if(luaState == nullptr)
            throw ConfigFileException("Error: ConfigFile init() - lua parser");

        luaL_openlibs(luaState);
    }

    ConfigFile::~ConfigFile(void)  noexcept{
         if(luaState != nullptr) cleanConfig();
    }

    void  ConfigFile::cleanConfig(void) noexcept{
         lua_close(luaState);
         luaState  =  nullptr;
    }

    void  ConfigFile::addLoadableVariable(string&& name, const char* dt, bool optional) anyexcept{
        if(name.empty()) throw ConfigFileException("Error: addOptionalLoadableVariable(): empty name.");

        auto [iterator, result] { configEnv.emplace(name, dt) };
        auto& configValue { iterator->second };
        configValue.setOptional(optional);
    }

    void  ConfigFile::addLoadableVariable(string&& name, string dt, bool optional) anyexcept{
        if(name.empty()) throw ConfigFileException("Error: addOptionalLoadableVariable(): empty name.");

        auto [iterator, result] { configEnv.emplace(name, dt) };
        auto& configValue { iterator->second };
        configValue.setOptional(optional);
    }

    void  ConfigFile::addLoadableVariable(string&& name, long dt, bool optional) anyexcept{
        if(name.empty()) throw ConfigFileException("Error: addOptionalLoadableVariable(): empty name.");

        auto [iterator, result] { configEnv.emplace(name, dt) };
        auto& configValue { iterator->second };
        configValue.setOptional(optional);
    }

    void  ConfigFile::addLoadableVariable(string&& name, double dt, bool optional) anyexcept{
        if(name.empty()) throw ConfigFileException("Error: addOptionalLoadableVariable(): empty name.");

        auto [iterator, result] { configEnv.emplace(name, dt) };
        auto& configValue { iterator->second };
        configValue.setOptional(optional);
    }

    void  ConfigFile::addLoadableVariable(string&& name, bool dt, bool optional) anyexcept{
        if(name.empty()) throw ConfigFileException("Error: addOptionalLoadableVariable(): empty name.");

        auto [iterator, result] { configEnv.emplace(name, dt) };
        auto& configValue { iterator->second };
        configValue.setOptional(optional);
    }

    string  ConfigFile::loadString(const string& key) anyexcept{
        string ret;
        lua_getglobal(luaState, key.c_str());
        if(lua_isnil(luaState, -1) == 1 ){
            throw ConfigFileException(mergeStrings({"Error: loadString() - invalid variable : ", key.c_str()}));
        }else{
            if(lua_isstring(luaState, -1) == 0)
                throw ConfigFileException(mergeStrings({"Error: loadString(): invalid type : ", key.c_str()}));
            ret  =   lua_tostring(luaState, -1);
        }
        lua_pop(luaState, 1);

        return ret;
    }

    long  ConfigFile::loadInteger(const string& key) anyexcept{
        long int ret;
        lua_getglobal(luaState, key.c_str());
        if(lua_isnil(luaState, -1) == 0 ){
            int      indicator;

            ret  =  lua_tointegerx(luaState, -1, &indicator);
            if(indicator == 0)
                throw ConfigFileException(mergeStrings({"Error: loadInteger(): invalid value : ", key.c_str()}));
        } else {
          throw ConfigFileException(mergeStrings({"Error: loadInteger() - invalid variable : ", key.c_str()}));
        }

        lua_pop(luaState, 1);

        return ret;
    }

    double  ConfigFile::loadFloat(const string& key) anyexcept{
        double ret;
        lua_getglobal(luaState, key.c_str());
        if(lua_isnil(luaState, -1) == 0 ){
            int      indicator;

            ret  =  lua_tonumberx(luaState, -1, &indicator);
            if(indicator == 0)
                 throw ConfigFileException(mergeStrings({"Error: loadFloat(): invalid value : ", key.c_str()}));
        } else {
          throw ConfigFileException(mergeStrings({"Error: loadFloat() - invalid variable : ", key.c_str()}));
        }

        lua_pop(luaState, 1);

        return ret;
    }

    bool ConfigFile::loadBool(const string& key)  anyexcept{
        bool ret;
        lua_getglobal(luaState, key.c_str());
        if(lua_isnil(luaState, -1) == 0 )
            ret  =  lua_toboolean(luaState, -1);
        else
            throw ConfigFileException(mergeStrings({"Error: loadBool() - invalid variable : ", key.c_str()}));

        lua_pop(luaState, 1);

        return ret;
    }

    void  ConfigFile::loadConfig(void)  anyexcept{
        if(luaL_loadfile(luaState, configurationFile.c_str()) != 0)
            throw ConfigFileException("Error: Invalid config file name.");

        if(lua_pcall(luaState, 0, 0, 0) != 0)
            throw ConfigFileException("Error: syntax error in config file.");

        bool optionalConf {true};
        try{
            for (auto &[key, value] : configEnv){
                try{
                    optionalConf = value.isOptional();
                    switch(value.getDataType()){
                        case DATA_TYPE::BOOLEAN :
                              configEnv.at(key).setBool(loadBool(key));
                              configEnv.at(key).setEmpty(false);
                           break;
                        case DATA_TYPE::FLOATING_POINT :
                              configEnv.at(key).setFloat(loadFloat(key));
                              configEnv.at(key).setEmpty(false);
                           break;
                        case DATA_TYPE::INTEGER :
                              configEnv.at(key).setInteger(loadInteger(key));
                              configEnv.at(key).setEmpty(false);
                           break;
                            case DATA_TYPE::TEXT :
                              configEnv.at(key).setText(loadString(key));
                              configEnv.at(key).setEmpty(false);
                           break;
                        default:
                           throw ConfigFileException("Error: loadConfig() - invalid data type.");
                    }
                }catch(ConfigFileException& ex){
                    if(!optionalConf) throw ex;
                }
            }
        }catch(out_of_range& ex){
            throw ConfigFileException(mergeStrings({"Error: loadconfig: ", ex.what()}));
        }
    }

    const ConfigVar& ConfigFile::getConf(const string& key) anyexcept{
        try{
            return configEnv.at(key);
        }catch(...){
          throw ConfigFileException(mergeStrings({"Error: getConf() - invalid key: ", key.c_str()}));
       }
    }

     ConfigVar& ConfigFile::setConf(const string& key) anyexcept {
        try{
            return configEnv.at(key);
        }catch(...){
          throw ConfigFileException(mergeStrings({"Error: getConf() - invalid key: ", key.c_str()}));
       }
     }

    ConfigScript::ConfigScript(const string& script) noexcept
        : scriptFile{ script }

    {}

    ConfigScript::~ConfigScript(void)  noexcept{
         cleanConfig();
    }

    void  ConfigScript::init(void)  anyexcept{
        luaStateScript = luaL_newstate();
        if(luaStateScript == nullptr)
            throw ConfigFileException(" Error : ConfigScript init()- lua parser");

        luaL_openlibs(luaStateScript);

        lua_pushcfunction(luaStateScript, ArpCtx::send);
        lua_setglobal(luaStateScript, "send");
        lua_pushcfunction(luaStateScript, ArpCtx::setSrcHdrMAC);
        lua_setglobal(luaStateScript, "setSrcHdrMAC");
        lua_pushcfunction(luaStateScript, ArpCtx::setDestHdrMAC);
        lua_setglobal(luaStateScript, "setDestHdrMAC");
        lua_pushcfunction(luaStateScript, ArpCtx::setFrameType);
        lua_setglobal(luaStateScript, "setFrameType");
        lua_pushcfunction(luaStateScript, ArpCtx::setHardType);
        lua_setglobal(luaStateScript, "setHardType");
        lua_pushcfunction(luaStateScript, ArpCtx::setProtType);
        lua_setglobal(luaStateScript, "setProtType");
        lua_pushcfunction(luaStateScript, ArpCtx::setHardSize);
        lua_setglobal(luaStateScript, "setHardSize");
        lua_pushcfunction(luaStateScript, ArpCtx::setProtSize);
        lua_setglobal(luaStateScript, "setProtSize");
        lua_pushcfunction(luaStateScript, ArpCtx::setOpcode);
        lua_setglobal(luaStateScript, "setOpcode");
        lua_pushcfunction(luaStateScript, ArpCtx::setDestMAC);
        lua_setglobal(luaStateScript, "setDestMAC");
        lua_pushcfunction(luaStateScript, ArpCtx::setDestIp);
        lua_setglobal(luaStateScript, "setDestIp");
        lua_pushcfunction(luaStateScript, ArpCtx::setSrcMAC);
        lua_setglobal(luaStateScript, "setSrcMAC");
        lua_pushcfunction(luaStateScript, ArpCtx::setSrcIp);
        lua_setglobal(luaStateScript, "setSrcIp");
    }

    void  ConfigScript::loadConfig(void)  anyexcept{
        if( luaL_dofile(luaStateScript, scriptFile.c_str()) != LUA_OK)
             throw ConfigFileException(lua_tostring(luaStateScript, -1));
    }

    void  ConfigScript::cleanConfig(void) noexcept{
         if(luaStateScript != nullptr) {
            lua_close(luaStateScript);
            luaStateScript  =  nullptr;
         }
    }

    ConfigFileException::ConfigFileException(string& errString)
      :   errorMessage{errString}
    {}

    ConfigFileException::ConfigFileException(string&& errString)
      :   errorMessage{errString}
    {}

    const char* ConfigFileException::what() const noexcept{
       return errorMessage.c_str();
    }

    void  ArpCtx::init(arplib::ArpsocketScript* arpsck, ConfigFile* cfile) noexcept{
          ArpCtx::arpsocket = arpsck;
          ArpCtx::configFile = cfile;
    }

    const ArpsocketScript* ArpCtx::getArpSckInstance(void)  noexcept{
          return ArpCtx::arpsocket;
    }

    int  ArpCtx::send( [[maybe_unused]] lua_State *L) noexcept{
         ArpCtx::arpsocket->send();
         return 0;
    }

    int ArpCtx::setSrcHdrMAC(lua_State *L)  anyexcept{
         const string par { luaL_checkstring (L, 1) };
         try{
             MacAddr mac = move(parseMAC(par));
             ArpCtx::configFile->setConf("hdrSenderMAC").setText(move(par));
             ArpCtx::arpsocket->setSrcHdrMAC(mac);
         } catch(StringUtilsException& ex){
             throw ConfigFileException(mergeStrings({"Error: setSrcHdrMAC :", ex.what()}));
         }

         return 0;
    }

    int ArpCtx::setDestHdrMAC(lua_State *L) anyexcept{
         const string par { luaL_checkstring (L, 1) };
         try{
             MacAddr mac = move(parseMAC(par));
             ArpCtx::configFile->setConf("hdrTargetMAC").setText(move(par));
             ArpCtx::arpsocket->setDestHdrMAC(mac);
         } catch(StringUtilsException& ex){
             throw ConfigFileException(mergeStrings({"Error: setDestHdrMAC :", ex.what()}));
         }
         return 0;
    }

    int ArpCtx::setFrameType(lua_State *L) anyexcept{
        try{
            const uint16_t par { safeUint16(luaL_checkinteger(L, 1))};
            ArpCtx::configFile->setConf("frameType").setInteger(par);
            ArpCtx::arpsocket->setFrameType(par);
        } catch (TypesUtilsException& ex){
          throw ConfigFileException(mergeStrings({"Error: setFrameType() - invalid value: ", ex.what()}));
        }
        return 0;
    }

    int ArpCtx::setHardType(lua_State *L) anyexcept{
        try{
            const uint16_t par { safeUint16(luaL_checkinteger(L, 1))};
            ArpCtx::configFile->setConf("hardType").setInteger(par);
            ArpCtx::arpsocket->setHardType(par);
        } catch (TypesUtilsException& ex){
          throw ConfigFileException(mergeStrings({"Error: setHardType() - invalid value: ", ex.what()}));
        }
        return 0;
    }

    int ArpCtx::setProtType(lua_State *L) anyexcept{
        try{
            const uint16_t par { safeUint16(luaL_checkinteger(L, 1))};
            ArpCtx::configFile->setConf("protType").setInteger(par);
            ArpCtx::arpsocket->setProtType(par);
        } catch (TypesUtilsException& ex){
          throw ConfigFileException(mergeStrings({"Error: setProtType() - invalid value: ", ex.what()}));
        }
        return 0;
    }

    int ArpCtx::setHardSize(lua_State *L) anyexcept{
        try{
            const uint8_t par { safeUint8(luaL_checkinteger(L, 1))};
            ArpCtx::configFile->setConf("hardSize").setInteger(par);
            ArpCtx::arpsocket->setHardSize(par);
        } catch (TypesUtilsException& ex){
          throw ConfigFileException(mergeStrings({"Error: setHardSize() - invalid value: ", ex.what()}));
        }
        return 0;
    }

    int ArpCtx::setProtSize(lua_State *L) anyexcept{
        try{
            const uint8_t par { safeUint8(luaL_checkinteger(L, 1))};
            ArpCtx::configFile->setConf("protSize").setInteger(par);
            ArpCtx::arpsocket->setProtSize(par);
        } catch (TypesUtilsException& ex){
          throw ConfigFileException(mergeStrings({"Error: setProtSize() - invalid value: ", ex.what()}));
        }
        return 0;
    }

    int ArpCtx::setOpcode(lua_State *L)  anyexcept{
        try{
            const uint16_t par { safeUint16(luaL_checkinteger(L, 1))};
            ArpCtx::configFile->setConf("opcode").setInteger(par);
            ArpCtx::arpsocket->setOpcode(par);
        } catch (TypesUtilsException& ex){
          throw ConfigFileException(mergeStrings({"Error: setOpcode() - invalid value: ", ex.what()}));
        }
        return 0;
    }

    int ArpCtx::setDestMAC(lua_State *L) anyexcept{
         const string par { luaL_checkstring (L, 1) };
         try{
             MacAddr mac = move(parseMAC(par));
             ArpCtx::configFile->setConf("targetMAC").setText(move(par));
             ArpCtx::arpsocket->setDestMAC(mac);
         } catch(StringUtilsException& ex){
             throw ConfigFileException(mergeStrings({"Error: setDestMAC :", ex.what()}));
         }
         return 0;
    }

    int ArpCtx::setDestIp(lua_State *L) anyexcept{
         try{
             const string par { luaL_checkstring (L, 1) };
             parseIpCheckOnly(par);
             ArpCtx::configFile->setConf("targetIp").setText(move(par));
             ArpCtx::arpsocket->setDestIp(par);
         } catch(StringUtilsException& ex){
             throw ConfigFileException(mergeStrings({"Error: setDestIp :", ex.what()}));
         }
         return 0;
    }

    int ArpCtx::setSrcMAC(lua_State *L) anyexcept{
         try{
             const string par { luaL_checkstring (L, 1) };
             MacAddr mac = move(parseMAC(par));
             ArpCtx::configFile->setConf("senderMAC").setText(move(par));
             ArpCtx::arpsocket->setSrcMAC(mac);
         } catch(StringUtilsException& ex){
             throw ConfigFileException(mergeStrings({"Error: setSrcMAC :", ex.what()}));
         }
         return 0;
    }

    int  ArpCtx::setSrcIp(lua_State *L) anyexcept{
         try{
             const string par { luaL_checkstring (L, 1) };
             parseIpCheckOnly(par);
             ArpCtx::configFile->setConf("senderIp").setText(move(par));
             ArpCtx::arpsocket->setSrcIp(par);
         } catch(StringUtilsException& ex){
             throw ConfigFileException(mergeStrings({"Error: setSrcIp :", ex.what()}));
         }
         return 0;
    }

} // End namespace configFile
