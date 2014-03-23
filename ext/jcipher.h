
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See MIT-LICENSE for the extact license
 */

#ifndef __JCIPHER_H__
#define __JCIPHER_H__

#include "jbase.h"

// Crypto++ headers...

#include "modes.h"

class JCipher : public JBase
{
  public:
    JCipher();

    string getModeName() const;
    static string getModeName(const enum ModeEnum mode);
    enum ModeEnum getMode() const;
    void setMode(const enum ModeEnum mode);

    string getPaddingName() const;
    static string getPaddingName(const enum PaddingEnum padding);
    enum PaddingEnum getPadding() const;
    enum PaddingEnum setPadding(const enum PaddingEnum padding);

    unsigned int getRounds() const;
    unsigned int setRounds(const unsigned int rounds);
    virtual unsigned int getValidRounds(const unsigned int rounds) const = 0;

  protected:
    enum ModeEnum itsMode;
    enum PaddingEnum itsPadding;
    unsigned int itsRounds;
};

#endif
