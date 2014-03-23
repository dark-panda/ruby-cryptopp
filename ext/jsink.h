
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JSINK_H__
#define __JSINK_H__

#include "filters.h"
#include "argnames.h"

extern "C" {
#include "ruby.h"

#if defined(RUBY_VERSION_CODE) && RUBY_VERSION_CODE >= 190
#include "ruby/io.h"
#else
#include "rubyio.h"
#endif
}

using namespace CryptoPP;

class RubyIOStore : public Store, private FilterPutSpaceHelper
{
  public:
    class Err : public Exception
    {
      public:
        Err(const std::string& s) : Exception(IO_ERROR, s) {}
    };

    class OpenErr : public Err
    {
      public:
        OpenErr(const std::string& filename) : Err("RubyIOStore: error opening IO stream for reading: " + filename) {}
    };

    class ReadErr : public Err
    {
      public:
        ReadErr() : Err("RubyIOStore: error reading IO stream") {}
    };

    RubyIOStore() {}

    RubyIOStore(VALUE** in)
    {
      StoreInitialize(MakeParameters(Name::InputStreamPointer(), *in));
    }

    RubyIOStore(const char* filename)
    {
      StoreInitialize(MakeParameters(Name::InputFileName(), filename));
    }

    VALUE* GetStream()
    {
      return m_stream;
    }

    size_t Peek(byte &outByte) const;
    size_t TransferTo2(BufferedTransformation &target, CryptoPP::lword &transferBytes, const std::string &channel = NULL_CHANNEL, bool blocking = true);

    // These abstract methods are purposely no-ops here...
    size_t CopyRangeTo2(BufferedTransformation& target, CryptoPP::lword& begin, CryptoPP::lword end = ULONG_MAX, const std::string& channel = NULL_CHANNEL, bool blocking = true) const { return 0; }
    CryptoPP::lword MaxRetrievable() const { return 0L; }

  private:
    void StoreInitialize(const NameValuePairs &parameters);
    VALUE* m_stream;

    byte* m_space;
    unsigned int m_len;
    bool m_waiting;
};

class RubyIOSource : public SourceTemplate<RubyIOStore>
{
  public:
    typedef RubyIOStore::Err Err;
    typedef RubyIOStore::OpenErr OpenErr;
    typedef RubyIOStore::ReadErr ReadErr;

    RubyIOSource(BufferedTransformation* attachment = NULL) : SourceTemplate<RubyIOStore>(attachment) {}

    RubyIOSource(VALUE** in, bool pumpAll, BufferedTransformation* attachment = NULL) : SourceTemplate<RubyIOStore>(attachment)
    {
      SourceInitialize(pumpAll, MakeParameters(Name::InputStreamPointer(), *in));
    }

    RubyIOSource(const char* filename, bool pumpAll, BufferedTransformation* attachment = NULL, bool binary = true) : SourceTemplate<RubyIOStore>(attachment)
    {
      SourceInitialize(pumpAll, MakeParameters(Name::InputFileName(), filename)(Name::InputBinaryMode(), binary));
    }

    VALUE* GetStream()
    {
      return m_store.GetStream();
    }
};


class RubyIOSink : public Sink
{
  public:
    class Err : public Exception
    {
      public:
        Err(const std::string& s) : Exception(IO_ERROR, s) {}
    };

    class OpenErr : public Err
    {
      public:
        OpenErr(const std::string &filename) : Err("RubyIOSink: error opening file for writing: " + filename) {}
    };

    class WriteErr : public Err
    {
      public:
        WriteErr() : Err("RubyIOSink: error writing file") {}
    };

    RubyIOSink()
    {
      m_stream = NULL;
    }

    RubyIOSink(VALUE** out)
    {
      IsolatedInitialize(MakeParameters(Name::OutputStreamPointer(), *out));
    }

    RubyIOSink(const char* filename, bool binary = true)
    {
      IsolatedInitialize(MakeParameters(Name::OutputFileName(), filename)(Name::OutputBinaryMode(), binary));
    }

    VALUE* GetStream()
    {
      return m_stream;
    }

    void IsolatedInitialize(const NameValuePairs& parameters);
    size_t Put2(const byte* inString, size_t length, int messageEnd, bool blocking);

    // IsolatedFlush isn't actually used, but needs to be implemented because
    // it's abstract...
    bool IsolatedFlush(bool hardFlush, bool blocking) { return false; };

  private:
    VALUE* m_stream;
};

#endif
