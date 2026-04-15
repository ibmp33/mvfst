/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/backend/openssl/certificate/CertUtils.h>
#include <fizz/server/DefaultCertManager.h>
#include <folly/FileUtil.h>
#include <folly/Synchronized.h>
#include <quic/common/MvfstLogging.h>

#include <random>

#include <quic/QuicConstants.h>
#include <quic/common/BufUtil.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/ServerCongestionControllerFactory.h>
#include <quic/logging/FileQLogger.h>
#include <quic/samples/echo/EchoHandler.h>
#include <quic/samples/echo/LogQuicStats.h>
#include <quic/server/QuicServer.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/QuicSharedUDPSocketFactory.h>

namespace quic::samples {

class EchoServerTransportFactory : public quic::QuicServerTransportFactory {
 public:
  ~EchoServerTransportFactory() override {
    draining_ = true;
    echoHandlers_.withWLock([](auto& echoHandlers) {
      while (!echoHandlers.empty()) {
        auto& handler = echoHandlers.back();
        handler->getEventBase()->runImmediatelyOrRunInEventBaseThreadAndWait(
            [&] {
              // The evb should be performing a sequential consistency atomic
              // operation already, so we can bank on that to make sure the
              // writes propagate to all threads.
              echoHandlers.pop_back();
            });
      }
    });
  }

  explicit EchoServerTransportFactory(
      bool useDatagrams = false,
      quic::BufPtr fixedResponse = nullptr,
      std::string qlogDir = "")
      : useDatagrams_(useDatagrams),
        fixedResponse_(std::move(fixedResponse)),
        qlogDir_(std::move(qlogDir)) {}

  quic::QuicServerTransport::Ptr make(
      folly::EventBase* evb,
      std::unique_ptr<FollyAsyncUDPSocketAlias> sock,
      const folly::SocketAddress&,
      QuicVersion,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx) noexcept
      override {
    CHECK_EQ(evb, sock->getEventBase());
    if (draining_) {
      return nullptr;
    }
    auto echoHandler = std::make_unique<EchoHandler>(
        evb,
        useDatagrams_,
        fixedResponse_ ? fixedResponse_->clone() : nullptr);
    auto transport = quic::QuicServerTransport::make(
        evb, std::move(sock), echoHandler.get(), echoHandler.get(), ctx);
    const_cast<quic::QuicConnectionStateBase*>(transport->getState())
        ->udpSendPacketLen = 1200;
    if (!qlogDir_.empty()) {
      auto qlogger = std::make_shared<FileQLogger>(
          VantagePoint::Server,
          kHTTP3ProtocolType,
          qlogDir_,
          true /* prettyJson */,
          true /* streaming */);
      transport->setQLogger(std::move(qlogger));
    }
    echoHandler->setQuicSocket(transport);
    echoHandlers_.withWLock([&](auto& echoHandlers) {
      echoHandlers.push_back(std::move(echoHandler));
    });
    return transport;
  }

 private:
  bool useDatagrams_;
  quic::BufPtr fixedResponse_;
  std::string qlogDir_;
  folly::Synchronized<std::vector<std::unique_ptr<EchoHandler>>> echoHandlers_;
  bool draining_{false};
};

class EchoServer {
 public:
  explicit EchoServer(
      std::vector<std::string> alpns,
      const std::string& host = "::1",
      uint16_t port = 4433,
      bool useDatagrams = false,
      uint64_t activeConnIdLimit = 10,
      bool enableMigration = true,
      std::string serverCertPath = "",
      std::string serverKeyPath = "",
      std::string transferRoot = "",
      std::string qlogDir = "",
      uint64_t fixedResponseBytes = 1024 * 1024,
      quic::CongestionControlType congestionControl =
          quic::CongestionControlType::Cubic)
      : host_(host),
        port_(port),
        alpns_(std::move(alpns)),
        transferRoot_(std::move(transferRoot)),
        qlogDir_(std::move(qlogDir)),
        fixedResponseBytes_(fixedResponseBytes) {
    TransportSettings settings;
    settings.datagramConfig.enabled = useDatagrams;
    settings.selfActiveConnectionIdLimit = activeConnIdLimit;
    settings.disableMigration = !enableMigration;
    settings.defaultCongestionController = congestionControl;
    server_ = QuicServer::createQuicServer(std::move(settings));
    server_->setCongestionControllerFactory(
        std::make_shared<quic::ServerCongestionControllerFactory>());

    server_->setQuicServerTransportFactory(
        std::make_unique<EchoServerTransportFactory>(
            useDatagrams, createFixedResponse(), qlogDir_));
    server_->setTransportStatsCallbackFactory(
        std::make_unique<LogQuicStatsFactory>());
    auto serverCtx = createFizzServerContext(
        std::move(serverCertPath), std::move(serverKeyPath));
    serverCtx->setClock(std::make_shared<fizz::SystemClock>());
    serverCtx->setSupportedAlpns(std::move(alpns_));
    server_->setFizzContext(serverCtx);

    if (!transferRoot_.empty()) {
      MVLOG_INFO << "Configured transfer root: " << transferRoot_
                 << " (serving " << fixedResponseBytes_
                 << " bytes from 1MB.bin when present)";
    }
    if (!qlogDir_.empty()) {
      MVLOG_INFO << "Writing server qlog files to " << qlogDir_;
    }
  }

  ~EchoServer() {
    server_->shutdown();
  }

  void start() {
    // Create a SocketAddress and the default or passed in host.
    folly::SocketAddress addr1(host_.c_str(), port_);
    addr1.setFromHostPort(host_, port_);
    server_->start(addr1, 0);
    MVLOG_INFO << "Echo server started at: " << addr1.describe();
    eventbase_.loopForever();
  }

 private:
  quic::BufPtr createFixedResponse() {
    std::string payload;
    if (!transferRoot_.empty()) {
      auto responsePath = transferRoot_ + "/1MB.bin";
      CHECK(folly::readFile(responsePath.c_str(), payload))
          << "Failed to read fixed response from " << responsePath;
      MVLOG_INFO << "Loaded fixed response from " << responsePath
                 << " bytes=" << payload.size();
      return folly::IOBuf::copyBuffer(payload.data(), payload.size());
    }

    payload.resize(fixedResponseBytes_);
    std::mt19937 rng(0x5eed1234);
    std::uniform_int_distribution<int> dist(0, 255);
    for (auto& byte : payload) {
      byte = static_cast<char>(dist(rng));
    }
    MVLOG_INFO << "Generated fixed random response bytes=" << payload.size();
    return folly::IOBuf::copyBuffer(payload.data(), payload.size());
  }

  std::shared_ptr<fizz::server::FizzServerContext> createFizzServerContext(
      std::string serverCertPath,
      std::string serverKeyPath) {
    auto serverCtx = quic::test::createServerCtx();
    if (serverCertPath.empty() && serverKeyPath.empty()) {
      return serverCtx;
    }

    CHECK(
        !serverCertPath.empty() && !serverKeyPath.empty())
        << "Both server certificate and server key paths must be provided";

    std::string certData;
    std::string keyData;
    CHECK(folly::readFile(serverCertPath.c_str(), certData))
        << "Failed to read server certificate from " << serverCertPath;
    CHECK(folly::readFile(serverKeyPath.c_str(), keyData))
        << "Failed to read server key from " << serverKeyPath;

    auto cert = fizz::openssl::CertUtils::makeSelfCert(certData, keyData);
    auto certManager = std::make_unique<fizz::server::DefaultCertManager>();
    certManager->addCertAndSetDefault(std::move(cert));
    serverCtx->setCertManager(std::move(certManager));
    return serverCtx;
  }

  std::string host_;
  uint16_t port_;
  folly::EventBase eventbase_;
  std::shared_ptr<quic::QuicServer> server_;
  std::vector<std::string> alpns_;
  std::string transferRoot_;
  std::string qlogDir_;
  uint64_t fixedResponseBytes_;
};
} // namespace quic::samples
