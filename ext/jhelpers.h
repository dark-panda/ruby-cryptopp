
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JHELPERS_H__
#define __JHELPERS_H__

#include <string>
#include <cctype>

// Crypto++ headers...

#include "hex.h"
#include "osrng.h"

#include "jconstants.h"

typedef unsigned char byte;

using namespace std;

string bin2hex(const string bin, const bool uppercase = false);
string hex2bin(const string hex);

char* bin2hex(const char* bin, size_t length, const bool uppercase = false);
char* hex2bin(const char* hex, size_t length);

string generateIV(const unsigned int size, const enum RNGEnum rng = DEFAULT_RNG);

// used to check the bounds of things like keylengths,
// rounds to perform, etc.:

unsigned int checkBounds(unsigned int length, unsigned int min, unsigned int max, unsigned short int multiple = 1);

#endif
