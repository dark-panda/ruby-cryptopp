
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#include "jhelpers.h"

using namespace CryptoPP;

string bin2hex(const string bin, const bool uppercase)
{
  string retval;
  StringSource(bin, true, new HexEncoder(new StringSink(retval), uppercase));
  return retval;
}

string hex2bin(const string hex)
{
  string retval;
  StringSource(hex, true, new HexDecoder(new StringSink(retval)));
  return retval;
}

char* bin2hex(const char* bin, size_t length, const bool uppercase)
{
  char* retval = new char[length * 2 + 1];
  StringSource(bin, true, new HexEncoder(new ArraySink((byte*) retval, length * 2), uppercase));
  return retval;
}

char* hex2bin(const char* hex, size_t length)
{
  char* retval = new char[length / 2 + 1];
  StringSource(hex, true, new HexDecoder(new ArraySink((byte*) retval, length / 2)));
  return retval;
}

string generateIV(const unsigned int size, const enum RNGEnum rng)
{
  string retval;
  RandomNumberGenerator* randPool = NULL;

  #ifdef NONBLOCKING_RNG_AVAILABLE
  if (rng == NON_BLOCKING_RNG) {
    randPool = new NonblockingRng;
  }
  #endif

  #if defined(NONBLOCKING_RNG_AVAILABLE) && defined(BLOCKING_RNG_AVAILABLE)
  else
  #endif

  #ifdef BLOCKING_RNG_AVAILABLE
  if (rng == BLOCKING_RNG) {
    randPool = new BlockingRng;
  }
  #endif

  if (rng == RAND_RNG) {
    for (unsigned int i = 0; i < size; i++) {
      retval += (char)(255.0 * rand() / RAND_MAX);
    }
  }
  else if (randPool != NULL) {
    for (unsigned int i = 0; i < size; i++) {
      retval += (char) randPool->GenerateByte();
    }
    delete randPool;
  }

  return retval;
}

unsigned int checkBounds(unsigned int length, unsigned int min, unsigned int max, unsigned short int multiple)
{
  if (min == max) {
    return min;
  }
  else if (length < min) {
    return min;
  }
  else if (length > max) {
    return max;
  }
  else {
    return (length + multiple - 1) - ((length + multiple - 1) % multiple);
  }
}
