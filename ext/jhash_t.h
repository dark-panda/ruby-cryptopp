
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See MIT-LICENSE for the extact license
 */

#ifndef __JHASH_T_H__
#define __JHASH_T_H__

#include "jhash.h"

#include "files.h"

using namespace CryptoPP;

template <typename HASH, enum HashEnum TYPE>
class JHash_Template : public JHash
{
  public:
    JHash_Template(string plaintext = "");
    enum HashEnum getHashType() const;
    bool hash();
    bool validate();
    bool validate(string plaintext, string hashtext);
    string hashRubyIO(VALUE* in, bool hex = true);

    /* This is deprecated. It was used before using RubyIO. Use it
       if you're using this code in something other than the CryptoPP Ruby
       extension... */
    //string hashFile(const string filename, bool hex = true);
};

#define HASH_TYPE TYPE

template <typename HASH, enum HashEnum TYPE>
JHash_Template<HASH, TYPE>::JHash_Template(string plaintext) : JHash(plaintext)
{
  itsHashModule = new HASH;
}

template <typename HASH, enum HashEnum TYPE>
HashEnum JHash_Template<HASH, TYPE>::getHashType() const
{
  return TYPE;
}

template <typename HASH, enum HashEnum TYPE>
bool JHash_Template<HASH, TYPE>::hash()
{
  itsHashtext.erase();

  StringSource s(itsPlaintext, true, new HashFilter(*itsHashModule, new StringSink(itsHashtext)));
  return true;
}

template <typename HASH, enum HashEnum TYPE>
bool JHash_Template<HASH, TYPE>::validate()
{
  return validate(itsPlaintext, itsHashtext);
}

template <typename HASH, enum HashEnum TYPE>
bool JHash_Template<HASH, TYPE>::validate(string plaintext, string hashtext)
{
  if (itsHashModule == NULL) {
    throw;
  }

  return itsHashModule->VerifyDigest((const byte*) hashtext.data(), (const byte*) plaintext.data(), plaintext.length());
}

template <typename HASH, enum HashEnum TYPE>
string JHash_Template<HASH, TYPE>::hashRubyIO(VALUE* in, bool hex)
{
  if (itsHashModule == NULL) {
    throw;
  }

  string retval;
  try {
    if (hex) {
      RubyIOSource f(&in, true, new HashFilter(*itsHashModule, new HexEncoder(new StringSink(retval), false)));
    }
    else {
      RubyIOSource f(&in, true, new HashFilter(*itsHashModule, new StringSink(retval)));
    }
  }
  catch (Exception e) {
    throw e;
  }
  return retval;
}


/* This is deprecated. It was used before using RubyIO. Use it
   if you're using this code in something other than the CryptoPP Ruby
   extension... */
/*template <typename HASH, enum HashEnum TYPE>
string JHash_Template<HASH, TYPE>::hashFile(const string filename, bool hex)
{
  if (itsHashModule == NULL) {
    throw;
  }

  string retval;
  try {
    if (hex) {
      FileSource f(filename.c_str(), true, new HashFilter(*itsHashModule, new HexEncoder(new StringSink(retval), false)));
    }
    else {
      FileSource f(filename.c_str(), true, new HashFilter(*itsHashModule, new StringSink(retval)));
    }
  }
  catch (FileStore::OpenErr e) {
    throw e;
  }
  return retval;
}*/

#endif
