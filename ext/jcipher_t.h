
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JCIPHER_T_H__
#define __JCIPHER_T_H__

#include "jbasiccipherinfo.h"

template <typename INFO, enum CipherEnum TYPE, unsigned int DEFAULT_ROUNDS = 0, unsigned int MIN_ROUNDS = 0, unsigned int MAX_ROUNDS = 0>
class JCipher_Template : public JBasicCipherInfo<INFO, JCipher>
{
  public:
    JCipher_Template();

    inline unsigned int getValidRounds(const unsigned int rounds) const;
    inline enum CipherEnum getCipherType() const;
    inline unsigned int getBlockSize() const;

    bool encrypt();
    bool decrypt();

    bool encryptRubyIO(VALUE* in, VALUE* out);
    bool decryptRubyIO(VALUE* in, VALUE* out);

    /* These are deprecated. They were used before using RubyIO. Use them
       if you're using this code in something other than the CryptoPP Ruby
       extension... */
//     bool encryptFile(const string in, const string out);
//     bool decryptFile(const string in, const string out);

  protected:
    virtual BlockCipher* getEncryptionObject() = 0;
    virtual BlockCipher* getDecryptionObject() = 0;
};

template <typename INFO, enum CipherEnum TYPE, unsigned int DEFAULT_ROUNDS, unsigned int MIN_ROUNDS, unsigned int MAX_ROUNDS>
JCipher_Template<INFO, TYPE, DEFAULT_ROUNDS, MIN_ROUNDS, MAX_ROUNDS>::JCipher_Template()
{
  this->itsKeylength = INFO::DEFAULT_KEYLENGTH;
  this->itsRounds = DEFAULT_ROUNDS;
}

template <typename INFO, enum CipherEnum TYPE, unsigned int DEFAULT_ROUNDS, unsigned int MIN_ROUNDS, unsigned int MAX_ROUNDS>
unsigned int JCipher_Template<INFO, TYPE, DEFAULT_ROUNDS, MIN_ROUNDS, MAX_ROUNDS>::getValidRounds(const unsigned int rounds) const
{
  return checkBounds(rounds, MIN_ROUNDS, MAX_ROUNDS);
}

template <typename INFO, enum CipherEnum TYPE, unsigned int DEFAULT_ROUNDS, unsigned int MIN_ROUNDS, unsigned int MAX_ROUNDS>
CipherEnum JCipher_Template<INFO, TYPE, DEFAULT_ROUNDS, MIN_ROUNDS, MAX_ROUNDS>::getCipherType() const
{
  return TYPE;
}

template <typename INFO, enum CipherEnum TYPE, unsigned int DEFAULT_ROUNDS, unsigned int MIN_ROUNDS, unsigned int MAX_ROUNDS>
unsigned int JCipher_Template<INFO, TYPE, DEFAULT_ROUNDS, MIN_ROUNDS, MAX_ROUNDS>::getBlockSize() const
{
  return INFO::BLOCKSIZE;
}

template <typename INFO, enum CipherEnum TYPE, unsigned int DEFAULT_ROUNDS, unsigned int MIN_ROUNDS, unsigned int MAX_ROUNDS>
bool JCipher_Template<INFO, TYPE, DEFAULT_ROUNDS, MIN_ROUNDS, MAX_ROUNDS>::encrypt()
{
  BlockCipher* bc = NULL;
  CipherModeBase* cipher = NULL;

  bc = getEncryptionObject();

  if (bc != NULL) {
    switch (this->itsMode) {
      case ECB_MODE:
        cipher = new ECB_Mode_ExternalCipher::Encryption(*bc, (const byte*) this->itsIV.data());
      break;

      case CBC_MODE:
        cipher = new CBC_Mode_ExternalCipher::Encryption(*bc, (const byte*) this->itsIV.data());
      break;

      case CBC_CTS_MODE:
        cipher = new CBC_CTS_Mode_ExternalCipher::Encryption(*bc, (const byte*) this->itsIV.data());
      break;

      case CFB_MODE:
        cipher = new CFB_Mode_ExternalCipher::Encryption(*bc, (const byte*) this->itsIV.data());
      break;

      case CTR_MODE:
        cipher = new CTR_Mode_ExternalCipher::Encryption(*bc, (const byte*) this->itsIV.data());
      break;

      case OFB_MODE:
        cipher = new OFB_Mode_ExternalCipher::Encryption(*bc, (const byte*) this->itsIV.data());
      break;

      default:
        return false;
    }

    this->itsCiphertext.erase();
    StringSource(this->itsPlaintext, true, new StreamTransformationFilter(*cipher, new StringSink(this->itsCiphertext), (StreamTransformationFilter::BlockPaddingScheme) this->itsPadding));

    delete bc;
  }
  else {
    return false;
  }

  if (cipher != NULL) {
    delete cipher;
  }

  return true;
}

template <typename INFO, enum CipherEnum TYPE, unsigned int DEFAULT_ROUNDS, unsigned int MIN_ROUNDS, unsigned int MAX_ROUNDS>
bool JCipher_Template<INFO, TYPE, DEFAULT_ROUNDS, MIN_ROUNDS, MAX_ROUNDS>::decrypt()
{
  BlockCipher* bc = NULL;
  CipherModeBase* cipher = NULL;

  switch (this->itsMode) {
    case ECB_MODE:
    case CBC_MODE:
    case CBC_CTS_MODE:
      bc = getDecryptionObject();
    break;

    case CFB_MODE:
    case CTR_MODE:
    case OFB_MODE:
      bc = getEncryptionObject();
    break;

    default:
      return false;
  }

  if (bc != NULL) {
    switch (this->itsMode) {
      case ECB_MODE:
        cipher = new ECB_Mode_ExternalCipher::Decryption(*bc);
      break;

      case CBC_MODE:
        cipher = new CBC_Mode_ExternalCipher::Decryption(*bc, (const byte*) this->itsIV.data());
      break;

      case CBC_CTS_MODE:
        cipher = new CBC_CTS_Mode_ExternalCipher::Decryption(*bc, (const byte*) this->itsIV.data());
      break;

      case CFB_MODE:
        cipher = new CFB_Mode_ExternalCipher::Decryption(*bc, (const byte*) this->itsIV.data());
      break;

      case CTR_MODE:
        cipher = new CTR_Mode_ExternalCipher::Decryption(*bc, (const byte*) this->itsIV.data());
      break;

      case OFB_MODE:
        cipher = new OFB_Mode_ExternalCipher::Decryption(*bc, (const byte*) this->itsIV.data());
      break;

      default:
        return false;
    }

    this->itsPlaintext.erase();
    StringSource(this->itsCiphertext, true, new StreamTransformationFilter(*cipher, new StringSink(this->itsPlaintext), (StreamTransformationFilter::BlockPaddingScheme) this->itsPadding));

    delete bc;
  }
  else {
    return false;
  }

  if (cipher != NULL) {
    delete cipher;
  }

  return true;
}

template <typename INFO, enum CipherEnum TYPE, unsigned int DEFAULT_ROUNDS, unsigned int MIN_ROUNDS, unsigned int MAX_ROUNDS>
bool JCipher_Template<INFO, TYPE, DEFAULT_ROUNDS, MIN_ROUNDS, MAX_ROUNDS>::encryptRubyIO(VALUE* in, VALUE* out)
{
  BlockCipher* bc = NULL;
  CipherModeBase* cipher = NULL;

  bc = getEncryptionObject();

  if (bc != NULL) {
    switch (this->itsMode) {
      case ECB_MODE:
        cipher = new ECB_Mode_ExternalCipher::Encryption(*bc, (const byte*) this->itsIV.data());
      break;

      case CBC_MODE:
        cipher = new CBC_Mode_ExternalCipher::Encryption(*bc, (const byte*) this->itsIV.data());
      break;

      case CBC_CTS_MODE:
        cipher = new CBC_CTS_Mode_ExternalCipher::Encryption(*bc, (const byte*) this->itsIV.data());
      break;

      case CFB_MODE:
        cipher = new CFB_Mode_ExternalCipher::Encryption(*bc, (const byte*) this->itsIV.data());
      break;

      case CTR_MODE:
        cipher = new CTR_Mode_ExternalCipher::Encryption(*bc, (const byte*) this->itsIV.data());
      break;

      case OFB_MODE:
        cipher = new OFB_Mode_ExternalCipher::Encryption(*bc, (const byte*) this->itsIV.data());
      break;

      default:
        return false;
    }

    try {
      RubyIOSource(&in, true, new StreamTransformationFilter(*cipher, new RubyIOSink(&out), (StreamTransformationFilter::BlockPaddingScheme) this->itsPadding));
    }
    catch (RubyIOStore::OpenErr e) {
      delete bc;
      if (cipher != NULL)
        delete cipher;
      throw e;
    }

    delete bc;
  }
  else {
    return false;
  }

  if (cipher != NULL) {
    delete cipher;
  }

  return true;
}

template <typename INFO, enum CipherEnum TYPE, unsigned int DEFAULT_ROUNDS, unsigned int MIN_ROUNDS, unsigned int MAX_ROUNDS>
bool JCipher_Template<INFO, TYPE, DEFAULT_ROUNDS, MIN_ROUNDS, MAX_ROUNDS>::decryptRubyIO(VALUE* in, VALUE* out)
{
  BlockCipher* bc = NULL;
  CipherModeBase* cipher = NULL;

  switch (this->itsMode) {
    case ECB_MODE:
    case CBC_MODE:
    case CBC_CTS_MODE:
      bc = getDecryptionObject();
    break;

    case CFB_MODE:
    case CTR_MODE:
    case OFB_MODE:
      bc = getEncryptionObject();
    break;

    default:
      return false;
  }

  if (bc != NULL) {
    switch (this->itsMode) {
      case ECB_MODE:
        cipher = new ECB_Mode_ExternalCipher::Decryption(*bc);
      break;

      case CBC_MODE:
        cipher = new CBC_Mode_ExternalCipher::Decryption(*bc, (const byte*) this->itsIV.data());
      break;

      case CBC_CTS_MODE:
        cipher = new CBC_CTS_Mode_ExternalCipher::Decryption(*bc, (const byte*) this->itsIV.data());
      break;

      case CFB_MODE:
        cipher = new CFB_Mode_ExternalCipher::Decryption(*bc, (const byte*) this->itsIV.data());
      break;

      case CTR_MODE:
        cipher = new CTR_Mode_ExternalCipher::Decryption(*bc, (const byte*) this->itsIV.data());
      break;

      case OFB_MODE:
        cipher = new OFB_Mode_ExternalCipher::Decryption(*bc, (const byte*) this->itsIV.data());
      break;

      default:
        return false;
    }

    try {
      RubyIOSource(&in, true, new StreamTransformationFilter(*cipher, new RubyIOSink(&out), (StreamTransformationFilter::BlockPaddingScheme) this->itsPadding));
    }
    catch (RubyIOStore::OpenErr e) {
      delete bc;
      if (cipher != NULL)
        delete cipher;
      throw e;
    }

    delete bc;
  }
  else {
    return false;
  }

  if (cipher != NULL) {
    delete cipher;
  }

  return true;
}

/* These are deprecated. They were used before using RubyIO. Use them
   if you're using this code in something other than the CryptoPP Ruby
   extension... */
/*template <typename INFO, enum CipherEnum TYPE, unsigned int DEFAULT_ROUNDS, unsigned int MIN_ROUNDS, unsigned int MAX_ROUNDS>
bool JCipher_Template<INFO, TYPE, DEFAULT_ROUNDS, MIN_ROUNDS, MAX_ROUNDS>::encryptFile(const string in, const string out)
{
  BlockCipher* bc = NULL;
  CipherModeBase* cipher = NULL;

  bc = getEncryptionObject();

  if (bc != NULL) {
    switch (this->itsMode) {
      case ECB_MODE:
        cipher = new ECB_Mode_ExternalCipher::Encryption(*bc, (const byte*) this->itsIV.data());
      break;

      case CBC_MODE:
        cipher = new CBC_Mode_ExternalCipher::Encryption(*bc, (const byte*) this->itsIV.data());
      break;

      case CBC_CTS_MODE:
        cipher = new CBC_CTS_Mode_ExternalCipher::Encryption(*bc, (const byte*) this->itsIV.data());
      break;

      case CFB_MODE:
        cipher = new CFB_Mode_ExternalCipher::Encryption(*bc, (const byte*) this->itsIV.data());
      break;

      case CTR_MODE:
        cipher = new CTR_Mode_ExternalCipher::Encryption(*bc, (const byte*) this->itsIV.data());
      break;

      case OFB_MODE:
        cipher = new OFB_Mode_ExternalCipher::Encryption(*bc, (const byte*) this->itsIV.data());
      break;

      default:
        return false;
    }

    try {
      FileSource(in.c_str(), true, new StreamTransformationFilter(*cipher, new FileSink(out.c_str()), (StreamTransformationFilter::BlockPaddingScheme) this->itsPadding));
    }
    catch (FileStore::OpenErr e) {
      delete bc;
      if (cipher != NULL) {
        delete cipher;
      }
      throw e;
    }

    delete bc;
  }
  else {
    return false;
  }

  if (cipher != NULL) {
    delete cipher;
  }

  return true;
}

template <typename INFO, enum CipherEnum TYPE, unsigned int DEFAULT_ROUNDS, unsigned int MIN_ROUNDS, unsigned int MAX_ROUNDS>
bool JCipher_Template<INFO, TYPE, DEFAULT_ROUNDS, MIN_ROUNDS, MAX_ROUNDS>::decryptFile(const string in, const string out)
{
  BlockCipher* bc = NULL;
  CipherModeBase* cipher = NULL;

  switch (this->itsMode) {
    case ECB_MODE:
    case CBC_MODE:
    case CBC_CTS_MODE:
      bc = getDecryptionObject();
    break;

    case CFB_MODE:
    case CTR_MODE:
    case OFB_MODE:
      bc = getEncryptionObject();
    break;

    default:
      return false;
  }

  if (bc != NULL) {
    switch (this->itsMode) {
      case ECB_MODE:
        cipher = new ECB_Mode_ExternalCipher::Decryption(*bc);
      break;

      case CBC_MODE:
        cipher = new CBC_Mode_ExternalCipher::Decryption(*bc, (const byte*) this->itsIV.data());
      break;

      case CBC_CTS_MODE:
        cipher = new CBC_CTS_Mode_ExternalCipher::Decryption(*bc, (const byte*) this->itsIV.data());
      break;

      case CFB_MODE:
        cipher = new CFB_Mode_ExternalCipher::Decryption(*bc, (const byte*) this->itsIV.data());
      break;

      case CTR_MODE:
        cipher = new CTR_Mode_ExternalCipher::Decryption(*bc, (const byte*) this->itsIV.data());
      break;

      case OFB_MODE:
        cipher = new OFB_Mode_ExternalCipher::Decryption(*bc, (const byte*) this->itsIV.data());
      break;

      default:
        return false;
    }

    try {
      FileSource(in.c_str(), true, new StreamTransformationFilter(*cipher, new FileSink(out.c_str()), (StreamTransformationFilter::BlockPaddingScheme) this->itsPadding));
    }

    catch (FileStore::OpenErr e) {
      delete bc;
      if (cipher != NULL) {
        delete cipher;
      }
      throw e;
    }

    delete bc;
  }
  else {
    return false;
  }

  if (cipher != NULL) {
    delete cipher;
  }

  return true;
}
*/

#endif
