
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See MIT-LICENSE for the extact license
 */

#include "jsink.h"

void RubyIOStore::StoreInitialize(const NameValuePairs& parameters)
{
  m_stream = NULL;
  parameters.GetValue(Name::InputStreamPointer(), m_stream);
  m_waiting = false;
}

size_t RubyIOStore::Peek(byte& outByte) const
{
  if (!m_stream || rb_funcall(*m_stream, rb_intern("eof?"), 0)) {
    return 0;
  }
  else {
    return 1;
  }
}


size_t RubyIOStore::TransferTo2(BufferedTransformation& target, CryptoPP::lword& transferBytes, const std::string& channel, bool blocking)
{
  if (!m_stream) {
    transferBytes = 0;
    return 0;
  }

  lword size = transferBytes;
  transferBytes = 0;

  if (m_waiting) {
    goto output;
  }

  while (size && !RTEST(rb_funcall(*m_stream, rb_intern("eof?"), 0))) {
    {
      VALUE buffer;
      size_t spaceSize = 1024;
      m_space = HelpCreatePutSpace(target, channel, 1, UnsignedMin(size_t(0) - 1, size), spaceSize);

      buffer = rb_funcall(*m_stream, rb_intern("read"), 1, UINT2NUM(STDMIN(size, (lword) spaceSize)));
      if (TYPE(buffer) != T_STRING) {
        throw ReadErr();
      }
      memcpy(m_space, StringValuePtr(buffer), RSTRING_LEN(buffer));
      m_len = RSTRING_LEN(buffer);
    }
    size_t blockedBytes;
    output:
      blockedBytes = target.ChannelPutModifiable2(channel, m_space, m_len, 0, blocking);
      m_waiting = blockedBytes > 0;
      if (m_waiting) {
        return blockedBytes;
      }
      size -= m_len;
      transferBytes += m_len;
  }
  if (!RTEST(rb_funcall(*m_stream, rb_intern("eof?"), 0))) {
    throw ReadErr();
  }
  return 0;
}

void RubyIOSink::IsolatedInitialize(const NameValuePairs& parameters)
{
  m_stream = NULL;
  parameters.GetValue(Name::OutputStreamPointer(), m_stream);
}

size_t RubyIOSink::Put2(const byte* inString, size_t length, int messageEnd, bool blocking)
{
  if (!m_stream) {
    throw Err("RubyIOSink: output stream not opened");
  }

  rb_funcall(*m_stream, rb_intern("write"), 1, rb_str_new((const char*) inString, length));

  if (messageEnd) {
    rb_funcall(*m_stream, rb_intern("flush"), 0);
  }

  return 0;
}
