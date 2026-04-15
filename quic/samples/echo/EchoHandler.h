/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/IOBuf.h>
#include <quic/api/QuicSocket.h>
#include <quic/common/MvfstLogging.h>

#include <quic/common/BufUtil.h>

#include <array>
#include <iomanip>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

namespace quic::samples {
class EchoHandler : public quic::QuicSocket::ConnectionSetupCallback,
                    public quic::QuicSocket::ConnectionCallback,
                    public quic::QuicSocket::ReadCallback,
                    public quic::QuicSocket::WriteCallback,
                    public quic::QuicSocket::DatagramCallback {
 public:
  using StreamData = std::pair<BufQueue, bool>;

  explicit EchoHandler(
      folly::EventBase* evbIn,
      bool useDatagrams = false,
      quic::BufPtr fixedResponse = nullptr)
      : evb(evbIn),
        useDatagrams_(useDatagrams),
        fixedResponse_(std::move(fixedResponse)),
        enableH3Mode_(fixedResponse_ != nullptr) {}

  void setQuicSocket(std::shared_ptr<quic::QuicSocket> socket) {
    sock = socket;
    if (useDatagrams_) {
      auto res = sock->setDatagramCallback(this);
      CHECK(res.has_value()) << res.error();
    }
  }

  void onNewBidirectionalStream(quic::StreamId id) noexcept override {
    MVLOG_INFO << "Got bidirectional stream id=" << id;
    CHECK(sock->setReadCallback(id, this).has_value());
  }

  void onNewUnidirectionalStream(quic::StreamId id) noexcept override {
    MVLOG_INFO << "Got unidirectional stream id=" << id;
    CHECK(sock->setReadCallback(id, this).has_value());
  }

  void onStopSending(
      quic::StreamId id,
      quic::ApplicationErrorCode error) noexcept override {
    MVLOG_INFO << "Got StopSending stream id=" << id << " error=" << error;
  }

  void onConnectionEnd() noexcept override {
    MVLOG_INFO << "Socket closed";
  }

  void onConnectionSetupError(QuicError error) noexcept override {
    onConnectionError(std::move(error));
  }

  void onConnectionError(QuicError error) noexcept override {
    MVLOG_ERROR << "Socket error=" << toString(error.code) << " "
                << error.message;
  }

  void onTransportReady() noexcept override {
    if (!enableH3Mode_) {
      return;
    }
    createCriticalStreams();
  }

  void readAvailable(quic::StreamId id) noexcept override {
    MVLOG_INFO << "read available for stream id=" << id;

    auto res = sock->read(id, 0);
    if (res.hasError()) {
      MVLOG_ERROR << "Got error=" << toString(res.error());
      CHECK(sock->setReadCallback(id, nullptr).has_value());
      return;
    }
    if (input_.find(id) == input_.end()) {
      input_.emplace(id, std::make_pair(BufQueue(), false));
    }
    quic::BufPtr data = std::move(res.value().first);
    bool eof = res.value().second;
    auto dataLen = (data ? data->computeChainDataLength() : 0);
    MVLOG_INFO << "Got len=" << dataLen << " eof=" << uint32_t(eof)
               << " total=" << input_[id].first.chainLength() + dataLen
               << " data="
               << ((data) ? data->clone()->toString() : std::string());
    input_[id].first.append(std::move(data));
    input_[id].second = eof;
    if (enableH3Mode_) {
      handleH3StreamRead(id);
      return;
    }
    if (eof) {
      echo(id, input_[id]);
      MVLOG_INFO << "uninstalling read callback";
      CHECK(sock->setReadCallback(id, nullptr).has_value());
    }
  }

  void readError(quic::StreamId id, QuicError error) noexcept override {
    MVLOG_ERROR << "Got read error on stream=" << id
                << " error=" << toString(error);
    // A read error only terminates the ingress portion of the stream state.
    // Your application should probably terminate the egress portion via
    // resetStream
  }

  void onDatagramsAvailable() noexcept override {
    auto res = sock->readDatagrams();
    if (res.hasError()) {
      MVLOG_ERROR << "readDatagrams() error: " << res.error();
      return;
    }
    MVLOG_INFO << "received " << res->size() << " datagrams";
    echoDg(std::move(res.value()));
  }

  void onStreamWriteReady(quic::StreamId id, uint64_t maxToSend) noexcept
      override {
    MVLOG_INFO << "socket is write ready with maxToSend=" << maxToSend;
    echo(id, input_[id]);
  }

  void onStreamWriteError(quic::StreamId id, QuicError error) noexcept
      override {
    MVLOG_ERROR << "write error with stream=" << id
                << " error=" << toString(error);
  }

  folly::EventBase* getEventBase() {
    return evb;
  }

  folly::EventBase* evb;
  std::shared_ptr<quic::QuicSocket> sock;

 private:
  static constexpr uint64_t kH3FrameData = 0x0;
  static constexpr uint64_t kH3FrameHeaders = 0x1;
  static constexpr uint64_t kH3FrameSettings = 0x4;
  static constexpr uint64_t kH3StreamControl = 0x0;
  static constexpr uint64_t kH3StreamQpackEncoder = 0x2;
  static constexpr uint64_t kH3StreamQpackDecoder = 0x3;

  struct H3FrameHeader {
    uint64_t type;
    uint64_t length;
    size_t headerLen;
  };

  struct ParsedRequest {
    std::string method;
    std::string path;
    std::string authority;
  };

  struct HpackHuffmanNode {
    std::array<const HpackHuffmanNode*, 256> children{};
    uint8_t codeLen{0};
    uint8_t sym{0};
    bool leaf{false};
  };

  void createCriticalStreams() {
    auto createUniControlStream = [&](uint64_t streamType, BufPtr payload) {
      auto stream = sock->createUnidirectionalStream();
      CHECK(stream.has_value());
      MVLOG_INFO << "Created local unidirectional stream id=" << *stream
                 << " type=" << streamType;
      auto res = sock->setControlStream(*stream);
      CHECK(!res.has_value()) << uint32_t(res.value());

      auto out = encodeVarint(streamType);
      if (payload) {
        out->appendToChain(std::move(payload));
      }
      MVLOG_INFO << "Writing local control/QPACK stream id=" << *stream
                 << " bytes=" << out->computeChainDataLength()
                 << " raw=" << dumpBuf(out.get());

      auto writeRes = sock->writeChain(*stream, std::move(out), false, nullptr);
      CHECK(!writeRes.hasError()) << toString(writeRes.error());
      criticalStreams_.insert(*stream);
    };

    createUniControlStream(
        kH3StreamControl,
        encodeFrame(kH3FrameSettings, folly::IOBuf::copyBuffer("")));
    createUniControlStream(kH3StreamQpackEncoder, nullptr);
    createUniControlStream(kH3StreamQpackDecoder, nullptr);
  }

  void handleH3StreamRead(quic::StreamId id) {
    if (isUnidirectionalStream(id)) {
      handlePeerUniStream(id);
      return;
    }

    if (respondedStreams_.count(id)) {
      return;
    }

    auto request = input_[id].first.clone();
    if (!request) {
      return;
    }
    request->coalesce();
    auto data = folly::ByteRange(request->data(), request->length());
    auto maybeHeader = decodeFrameHeader(data);
    if (!maybeHeader.has_value()) {
      return;
    }
    auto frameHeader = *maybeHeader;
    MVLOG_INFO << "H3 request frame on stream=" << id
               << " type=" << frameHeader.type
               << " length=" << frameHeader.length
               << " buffered=" << data.size();
    if (data.size() < frameHeader.headerLen + frameHeader.length) {
      return;
    }

    respondedStreams_.insert(id);
    if (frameHeader.type != kH3FrameHeaders) {
      writeSimpleH3Response(id, 404, "not found");
      return;
    }
    data.advance(frameHeader.headerLen);
    auto headerPayload = data.subpiece(0, frameHeader.length);
    MVLOG_INFO << "H3 request HEADERS payload size=" << headerPayload.size()
               << " on stream=" << id;
    auto requestHeaders = decodeRequestHeaders(headerPayload);
    if (!requestHeaders.has_value()) {
      MVLOG_WARNING
          << "Failed to decode request headers, falling back to default "
             "/1MB.bin response";
    } else {
      if (requestHeaders->method != "GET") {
        writeSimpleH3Response(id, 404, "not found");
        return;
      }
      if (requestHeaders->path != "/1MB.bin") {
        writeSimpleH3Response(id, 404, "not found");
        return;
      }
      MVLOG_INFO << "Decoded request headers on stream=" << id
                 << " method=" << requestHeaders->method
                 << " path=" << requestHeaders->path
                 << " authority=" << requestHeaders->authority;
    }

    writeSimpleH3Response(
        id,
        200,
        fixedResponse_ ? fixedResponse_->clone() : folly::IOBuf::copyBuffer(""));
  }

  void handlePeerUniStream(quic::StreamId id) {
    auto streamData = input_[id].first.clone();
    if (!streamData) {
      return;
    }
    streamData->coalesce();
    auto data = folly::ByteRange(streamData->data(), streamData->length());
    if (!peerUniStreamTypes_.count(id)) {
      auto streamType = decodeVarint(data);
      if (!streamType.has_value()) {
        return;
      }
      peerUniStreamTypes_[id] = *streamType;
      auto typeLen = encodedVarintSize(data[0]);
      data.advance(typeLen);
      if (*streamType == kH3StreamControl ||
          *streamType == kH3StreamQpackEncoder ||
          *streamType == kH3StreamQpackDecoder) {
        auto res = sock->setControlStream(id);
        if (res.has_value()) {
          MVLOG_ERROR << "Failed to mark peer uni stream " << id
                      << " as control stream, error=" << uint32_t(*res);
        }
      }
    } else {
      auto typeLen = encodedVarintSize(data[0]);
      data.advance(typeLen);
    }

    if (peerUniStreamTypes_[id] != kH3StreamControl) {
      return;
    }

    while (!data.empty()) {
      auto frameHeader = decodeFrameHeader(data);
      if (!frameHeader.has_value()) {
        return;
      }
      if (data.size() < frameHeader->headerLen + frameHeader->length) {
        return;
      }
      if (frameHeader->type == kH3FrameSettings) {
        sawPeerSettings_ = true;
      }
      data.advance(frameHeader->headerLen + frameHeader->length);
    }
  }

  void writeSimpleH3Response(quic::StreamId id, int status, std::string body) {
    writeSimpleH3Response(id, status, folly::IOBuf::copyBuffer(body));
  }

  void writeSimpleH3Response(quic::StreamId id, int status, BufPtr body) {
    auto bodyLen = body ? body->computeChainDataLength() : 0;
    auto headerBlock = encodeHeaderBlock(status, bodyLen);
    MVLOG_INFO << "Response QPACK block on stream=" << id
               << " len=" << headerBlock->computeChainDataLength()
               << " raw=" << dumpBuf(headerBlock.get());
    auto headerFrame = encodeFrame(kH3FrameHeaders, std::move(headerBlock));
    auto headerFrameLen = headerFrame->computeChainDataLength();
    MVLOG_INFO << "Response HEADERS frame on stream=" << id
               << " len=" << headerFrameLen
               << " raw=" << dumpBuf(headerFrame.get());
    auto dataFrame = encodeFrame(kH3FrameData, std::move(body));
    auto dataFrameLen = dataFrame->computeChainDataLength();
    MVLOG_INFO << "Response DATA frame on stream=" << id
               << " len=" << dataFrameLen;
    MVLOG_INFO << "Writing H3 response on stream=" << id
               << " status=" << status
               << " headerFrameLen=" << headerFrameLen
               << " dataFrameLen=" << dataFrameLen
               << " fin=1";
    auto out = std::move(headerFrame);
    out->appendToChain(std::move(dataFrame));
    auto res = sock->writeChain(id, std::move(out), true, nullptr);
    if (res.hasError()) {
      MVLOG_ERROR << "write error=" << toString(res.error());
    } else {
      MVLOG_INFO << "H3 response write queued on stream=" << id
                 << " HEADERS+DATA+FIN";
      CHECK(sock->setReadCallback(id, nullptr).has_value());
    }
  }

  BufPtr encodeHeaderBlock(int status, uint64_t contentLength) {
    std::string block;
    block.push_back('\x00'); // Required Insert Count = 0
    block.push_back('\x00'); // Base = 0
    if (status == 200) {
      appendIndexedStaticFieldLine(block, 25); // :status = 200
    } else if (status == 404) {
      appendIndexedStaticFieldLine(block, 27); // :status = 404
    } else {
      appendLiteralHeader(block, ":status", std::to_string(status));
    }
    appendLiteralHeaderWithStaticNameRef(
        block, 4, std::to_string(contentLength)); // content-length
    appendLiteralHeader(
        block, "content-type", "application/octet-stream");
    return folly::IOBuf::copyBuffer(block);
  }

  void appendIndexedStaticFieldLine(std::string& block, uint64_t index) {
    appendPrefixedInteger(block, 0xC0, index, 0x3f);
  }

  void appendLiteralHeaderWithStaticNameRef(
      std::string& block,
      uint64_t nameIndex,
      const std::string& value) {
    appendPrefixedInteger(block, 0x50, nameIndex, 0x0f);
    appendPrefixedInteger(block, 0x00, value.size(), 0x7f);
    block.append(value);
  }

  void appendLiteralHeader(
      std::string& block,
      const std::string& name,
      const std::string& value) {
    appendPrefixedInteger(block, 0x20, name.size(), 0x07);
    block.append(name);
    appendPrefixedInteger(block, 0x00, value.size(), 0x7f);
    block.append(value);
  }

  std::string dumpBuf(const folly::IOBuf* buf) {
    if (!buf) {
      return "";
    }
    auto clone = buf->cloneCoalesced();
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (size_t i = 0; i < clone->length(); ++i) {
      if (i) {
        out << ' ';
      }
      out << std::setw(2)
          << static_cast<unsigned int>(clone->data()[i]);
    }
    return out.str();
  }

  BufPtr encodeFrame(uint64_t type, BufPtr payload) {
    auto out = encodeVarint(type);
    out->appendToChain(encodeVarint(payload ? payload->computeChainDataLength() : 0));
    if (payload) {
      out->appendToChain(std::move(payload));
    }
    return out;
  }

  BufPtr encodeVarint(uint64_t value) {
    std::string out;
    if (value < 64) {
      out.push_back(static_cast<char>(value));
    } else if (value < 16384) {
      out.push_back(static_cast<char>(0x40 | ((value >> 8) & 0x3f)));
      out.push_back(static_cast<char>(value & 0xff));
    } else {
      CHECK_LT(value, 1073741824ULL);
      out.push_back(static_cast<char>(0x80 | ((value >> 24) & 0x3f)));
      out.push_back(static_cast<char>((value >> 16) & 0xff));
      out.push_back(static_cast<char>((value >> 8) & 0xff));
      out.push_back(static_cast<char>(value & 0xff));
    }
    return folly::IOBuf::copyBuffer(out);
  }

  void appendPrefixedInteger(
      std::string& out,
      uint8_t firstByteMask,
      uint64_t value,
      uint8_t prefixMask) {
    if (value < prefixMask) {
      out.push_back(static_cast<char>(firstByteMask | value));
      return;
    }

    out.push_back(static_cast<char>(firstByteMask | prefixMask));
    value -= prefixMask;
    while (value >= 128) {
      out.push_back(static_cast<char>((value % 128) + 128));
      value /= 128;
    }
    out.push_back(static_cast<char>(value));
  }

  std::optional<uint64_t> decodeVarint(folly::ByteRange data) {
    if (data.empty()) {
      return std::nullopt;
    }
    auto first = data[0];
    auto prefix = first >> 6;
    size_t length = size_t{1} << prefix;
    if (data.size() < length) {
      return std::nullopt;
    }
    uint64_t value = first & 0x3f;
    for (size_t i = 1; i < length; ++i) {
      value = (value << 8) | data[i];
    }
    return value;
  }

  std::optional<H3FrameHeader> decodeFrameHeader(folly::ByteRange data) {
    auto type = decodeVarint(data);
    if (!type.has_value()) {
      return std::nullopt;
    }
    size_t typeLen = encodedVarintSize(data[0]);
    data.advance(typeLen);
    auto length = decodeVarint(data);
    if (!length.has_value()) {
      return std::nullopt;
    }
    size_t lengthLen = encodedVarintSize(data[0]);
    return H3FrameHeader{*type, *length, typeLen + lengthLen};
  }

  size_t encodedVarintSize(uint8_t firstByte) {
    return size_t{1} << (firstByte >> 6);
  }

  std::optional<ParsedRequest> decodeRequestHeaders(folly::ByteRange data) {
    ParsedRequest request;
    auto requiredInsertCount = decodePrefixedInteger(data, 8);
    if (!requiredInsertCount.has_value()) {
      return std::nullopt;
    }
    auto base = decodePrefixedInteger(data, 7);
    if (!base.has_value()) {
      return std::nullopt;
    }

    while (!data.empty()) {
      auto field = decodeHeaderField(data);
      if (!field.has_value()) {
        return std::nullopt;
      }
      MVLOG_INFO << "Decoded request header name=[" << field->first
                 << "] value=[" << field->second << "]";
      if (field->first == ":method") {
        request.method = field->second;
      } else if (field->first == ":path") {
        request.path = field->second;
      } else if (field->first == ":authority") {
        request.authority = field->second;
      }
    }

    return request;
  }

  std::optional<std::pair<std::string, std::string>> decodeHeaderField(
      folly::ByteRange& data) {
    if (data.empty()) {
      return std::nullopt;
    }

    auto first = data[0];
    if (first & 0x80) {
      auto index = decodePrefixedInteger(data, 6);
      if (!index.has_value()) {
        return std::nullopt;
      }
      auto entry = lookupStaticFieldLine(*index);
      if (!entry.has_value()) {
        MVLOG_INFO << "Ignoring unsupported static field line index="
                   << *index;
        return std::make_pair(std::string(), std::string());
      }
      return entry;
    }

    if ((first & 0xC0) == 0x40) {
      bool staticRef = (first & 0x10) != 0;
      auto index = decodePrefixedInteger(data, 4);
      if (!index.has_value() || !staticRef) {
        return std::nullopt;
      }
      auto name = lookupStaticHeaderName(*index);
      auto value = decodeStringLiteral(data, 7);
      if (!value.has_value()) {
        return std::nullopt;
      }
      if (!name.has_value()) {
        MVLOG_INFO << "Ignoring unsupported static name reference index="
                   << *index;
        return std::make_pair(std::string(), std::move(*value));
      }
      return std::make_pair(*name, *value);
    }

    if ((first & 0xE0) == 0x20) {
      auto name = decodeStringLiteral(data, 3);
      if (!name.has_value()) {
        return std::nullopt;
      }
      auto value = decodeStringLiteral(data, 7);
      if (!value.has_value()) {
        return std::nullopt;
      }
      return std::make_pair(*name, *value);
    }

    return std::nullopt;
  }

  std::optional<uint64_t> decodePrefixedInteger(
      folly::ByteRange& data,
      uint8_t prefixBits) {
    if (data.empty()) {
      return std::nullopt;
    }
    uint8_t mask = (1u << prefixBits) - 1;
    uint64_t value = data[0] & mask;
    data.advance(1);
    if (value < mask) {
      return value;
    }

    uint64_t multiplier = 1;
    while (!data.empty()) {
      auto byte = data[0];
      data.advance(1);
      value += uint64_t(byte & 0x7f) * multiplier;
      if ((byte & 0x80) == 0) {
        return value;
      }
      multiplier *= 128;
    }
    return std::nullopt;
  }

  std::optional<std::string> decodeStringLiteral(
      folly::ByteRange& data,
      uint8_t prefixBits) {
    if (data.empty()) {
      return std::nullopt;
    }
    bool huffman = (data[0] & (1u << prefixBits)) != 0;
    auto length = decodePrefixedInteger(data, prefixBits);
    if (!length.has_value() || data.size() < *length) {
      return std::nullopt;
    }
    std::string value;
    if (huffman) {
      auto decoded = decodeHuffmanString(data.subpiece(0, *length));
      if (!decoded.has_value()) {
        return std::nullopt;
      }
      value = std::move(*decoded);
    } else {
      value.assign(reinterpret_cast<const char*>(data.data()), *length);
    }
    data.advance(*length);
    return value;
  }

  std::optional<std::string> decodeHuffmanString(folly::ByteRange data) {
    auto root = getHpackHuffmanRoot();
    const HpackHuffmanNode* node = root;
    uint32_t cur = 0;
    uint8_t cbits = 0;
    uint8_t sbits = 0;
    std::string out;

    for (auto byte : data) {
      cur = (cur << 8) | byte;
      cbits += 8;
      sbits += 8;
      while (cbits >= 8) {
        auto idx = static_cast<uint8_t>(cur >> (cbits - 8));
        node = node->children[idx];
        if (!node) {
          MVLOG_ERROR << "Invalid HPACK Huffman data";
          return std::nullopt;
        }
        if (node->leaf) {
          out.push_back(static_cast<char>(node->sym));
          cbits -= node->codeLen;
          node = root;
          sbits = cbits;
        } else {
          cbits -= 8;
        }
      }
    }

    while (cbits > 0) {
      auto idx = static_cast<uint8_t>(cur << (8 - cbits));
      node = node->children[idx];
      if (!node) {
        MVLOG_ERROR << "Invalid HPACK Huffman tail";
        return std::nullopt;
      }
      if (!node->leaf || node->codeLen > cbits) {
        break;
      }
      out.push_back(static_cast<char>(node->sym));
      cbits -= node->codeLen;
      node = root;
      sbits = cbits;
    }

    if (sbits > 7) {
      MVLOG_ERROR << "Invalid HPACK Huffman padding length";
      return std::nullopt;
    }
    if (cbits > 0) {
      uint32_t mask = (1u << cbits) - 1;
      if ((cur & mask) != mask) {
        MVLOG_ERROR << "Invalid HPACK Huffman EOS padding";
        return std::nullopt;
      }
    }
    return out;
  }

  const HpackHuffmanNode* getHpackHuffmanRoot() {
    static const HpackHuffmanNode* root = []() {
      static std::vector<std::unique_ptr<HpackHuffmanNode>> internals;
      static std::array<HpackHuffmanNode, 256> leaves;
      static auto newInternal = []() {
        internals.push_back(std::make_unique<HpackHuffmanNode>());
        return internals.back().get();
      };

      auto rootNode = newInternal();
      for (size_t sym = 0; sym < kHpackHuffmanCodes.size(); ++sym) {
        auto code = kHpackHuffmanCodes[sym];
        auto codeLen = kHpackHuffmanCodeLens[sym];
        auto* cur = rootNode;
        auto remaining = codeLen;
        while (remaining > 8) {
          remaining -= 8;
          uint8_t idx = static_cast<uint8_t>(code >> remaining);
          if (!cur->children[idx]) {
            cur->children[idx] = newInternal();
          }
          cur = const_cast<HpackHuffmanNode*>(cur->children[idx]);
        }
        uint8_t shift = 8 - remaining;
        uint16_t start = static_cast<uint8_t>(code << shift);
        uint16_t end = 1u << shift;
        leaves[sym].leaf = true;
        leaves[sym].sym = static_cast<uint8_t>(sym);
        leaves[sym].codeLen = remaining;
        for (uint16_t i = start; i < start + end; ++i) {
          cur->children[i] = &leaves[sym];
        }
      }
      return rootNode;
    }();
    return root;
  }

  std::optional<std::string> lookupStaticHeaderName(uint64_t index) {
    switch (index) {
      case 0:
        return std::string(":authority");
      case 1:
        return std::string(":path");
      case 4:
        return std::string("content-length");
      case 17:
      case 18:
      case 19:
      case 20:
      case 21:
        return std::string(":method");
      case 22:
      case 23:
        return std::string(":scheme");
      case 25:
      case 27:
        return std::string(":status");
      case 31:
        return std::string("accept-encoding");
      default:
        return std::nullopt;
    }
  }

  std::optional<std::pair<std::string, std::string>> lookupStaticFieldLine(
      uint64_t index) {
    switch (index) {
      case 0:
        return std::make_pair(std::string(":authority"), std::string());
      case 1:
        return std::make_pair(std::string(":path"), std::string("/"));
      case 17:
        return std::make_pair(std::string(":method"), std::string("GET"));
      case 18:
        return std::make_pair(std::string(":method"), std::string("HEAD"));
      case 20:
        return std::make_pair(std::string(":method"), std::string("POST"));
      case 22:
        return std::make_pair(std::string(":scheme"), std::string("http"));
      case 23:
        return std::make_pair(std::string(":scheme"), std::string("https"));
      case 25:
        return std::make_pair(std::string(":status"), std::string("200"));
      case 27:
        return std::make_pair(std::string(":status"), std::string("404"));
      case 31:
        return std::make_pair(
            std::string("accept-encoding"),
            std::string("gzip, deflate, br"));
      default:
        return std::nullopt;
    }
  }

  bool isUnidirectionalStream(quic::StreamId id) const {
    return (id & 0x2) != 0;
  }

  void echo(quic::StreamId id, StreamData& data) {
    if (!data.second) {
      // only echo when eof is present
      return;
    }
    quic::BufPtr echoedData;
    if (fixedResponse_) {
      echoedData = fixedResponse_->clone();
    } else {
      echoedData = BufHelpers::copyBuffer("echo ");
      echoedData->appendToChain(data.first.move());
    }
    auto res = sock->writeChain(id, std::move(echoedData), true, nullptr);
    if (res.hasError()) {
      MVLOG_ERROR << "write error=" << toString(res.error());
    } else {
      // echo is done, clear EOF
      data.second = false;
    }
  }

  void echoDg(std::vector<quic::ReadDatagram> datagrams) {
    CHECK_GT(datagrams.size(), 0);
    for (const auto& datagram : datagrams) {
      auto echoedData = BufHelpers::copyBuffer("echo ");
      echoedData->appendToChain(datagram.bufQueue().front()->cloneCoalesced());
      auto res = sock->writeDatagram(std::move(echoedData));
      if (res.hasError()) {
        MVLOG_ERROR << "writeDatagram error=" << toString(res.error());
      }
    }
  }

  bool useDatagrams_;
  quic::BufPtr fixedResponse_;
  bool enableH3Mode_{false};
  using PerStreamData = std::map<quic::StreamId, StreamData>;
  PerStreamData input_;
  std::unordered_set<quic::StreamId> criticalStreams_;
  std::unordered_set<quic::StreamId> respondedStreams_;
  std::map<quic::StreamId, uint64_t> peerUniStreamTypes_;
  bool sawPeerSettings_{false};

  static constexpr std::array<uint32_t, 256> kHpackHuffmanCodes = {
      0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5,
      0xfffffe6, 0xfffffe7, 0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9,
      0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec, 0xfffffed, 0xfffffee,
      0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3,
      0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9,
      0xffffffa, 0xffffffb, 0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8,
      0x7fa, 0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18, 0x0, 0x1,
      0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc,
      0x20, 0xffb, 0x3fc, 0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
      0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
      0x6e, 0x6f, 0x70, 0x71, 0x72, 0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0,
      0x1ffc, 0x3ffc, 0x22, 0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26,
      0x27, 0x6, 0x74, 0x75, 0x28, 0x29, 0x2a, 0x7, 0x2b, 0x76, 0x2c, 0x8,
      0x9, 0x2d, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7ffe, 0x7fc, 0x3ffd,
      0x1ffd, 0xffffffc, 0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3,
      0x3fffd4, 0x3fffd5, 0x7fffd9, 0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc,
      0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf, 0xffffec, 0xffffed, 0x3fffd7,
      0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3, 0x7fffe4, 0x1fffdc,
      0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef, 0x3fffda,
      0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde,
      0x7fffea, 0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb,
      0x7fffec, 0x1fffe0, 0x1fffe1, 0x3fffe0, 0x1fffe2, 0x7fffed, 0x3fffe1,
      0x7fffee, 0x7fffef, 0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4, 0x7ffff0,
      0x3fffe5, 0x3fffe6, 0x7ffff1, 0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1,
      0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec, 0x3ffffe2, 0x3ffffe3,
      0x3ffffe4, 0x7ffffde, 0x7ffffdf, 0x3ffffe5, 0xfffff1, 0x1ffffed,
      0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7,
      0x7ffffe2, 0xfffff2, 0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9,
      0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5, 0xfffec, 0xfffff3,
      0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3, 0x3fffea,
      0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea,
      0x7ffff4, 0x3ffffeb, 0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7,
      0x7ffffe8, 0x7ffffe9, 0x7ffffea, 0x7ffffeb, 0xffffffe, 0x7ffffec,
      0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee};
  static constexpr std::array<uint8_t, 256> kHpackHuffmanCodeLens = {
      13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
      28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
      6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
      5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
      13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
      7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
      15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
      6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
      20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
      24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
      22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
      21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
      26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
      19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
      20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
      26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26};
};
} // namespace quic::samples
