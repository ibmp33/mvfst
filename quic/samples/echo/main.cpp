/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>

#include <fizz/crypto/Utils.h>
#include <folly/init/Init.h>
#include <folly/SocketAddress.h>
#include <folly/portability/GFlags.h>
#include <folly/String.h>

#include <quic/samples/echo/EchoClient.h>
#include <quic/samples/echo/EchoServer.h>
#include <quic/samples/echo/EchoTransportServer.h>

DEFINE_string(host, "::1", "Echo server hostname/IP");
DEFINE_int32(port, 4433, "Echo server port");
DEFINE_string(addr, "", "Server address in host:port form");
DEFINE_string(listen, "", "Server listen address in host:port form");
DEFINE_string(
    mode,
    "server",
    "Mode to run in: 'client', 'server', transport-server");
DEFINE_string(
    token,
    "",
    "Client new token string to attach to connection initiation");
DEFINE_bool(use_datagrams, false, "Use QUIC datagrams to communicate");
DEFINE_int64(
    active_conn_id_limit,
    10,
    "Maximum number of active connection IDs a peer supports");
DEFINE_bool(enable_migration, true, "Enable/disable migration");
DEFINE_string(alpns, "h3", "Comma separated ALPN list");
DEFINE_bool(
    connect_only,
    false,
    "Client specific; connect and exit when set to true");
DEFINE_string(client_cert_path, "", "Client certificate file path");
DEFINE_string(client_key_path, "", "Client private key file path");
DEFINE_string(server_cert_path, "", "Server certificate file path");
DEFINE_string(server_key_path, "", "Server private key file path");
DEFINE_string(cert, "", "Alias for --server_cert_path");
DEFINE_string(key, "", "Alias for --server_key_path");
DEFINE_string(
    transfer_root,
    "",
    "Root directory reserved for large file transfer workflows");
DEFINE_string(root, "", "Alias for --transfer_root");
DEFINE_string(
    congestion_control,
    "cubic",
    "Congestion control algorithm: cubic, bbr, bbr2, bbr2modular, copa, newreno, staticcwnd, none");
DEFINE_string(
    cc_algorithm,
    "",
    "Alias for --congestion_control. Also accepts reno as newreno");
DEFINE_string(
    qlog_dir,
    "",
    "Reserved qlog output directory. Echo sample does not write qlog files yet");
DEFINE_uint64(
    response_bytes,
    1024 * 1024,
    "Server fixed response payload size when transfer_root/1MB.bin is absent");

using namespace quic::samples;

int main(int argc, char* argv[]) {
#if FOLLY_HAVE_LIBGFLAGS
  // Enable glog logging to stderr by default.
  gflags::SetCommandLineOptionWithMode(
      "logtostderr", "1", gflags::SET_FLAGS_DEFAULT);
#endif
  gflags::ParseCommandLineFlags(&argc, &argv, false);
  folly::Init init(&argc, &argv);
  fizz::CryptoUtils::init();

  std::vector<std::string> alpns;
  folly::split(',', FLAGS_alpns, alpns);

  auto host = FLAGS_host;
  auto port = static_cast<uint16_t>(FLAGS_port);
  const auto& addrArg = !FLAGS_listen.empty() ? FLAGS_listen : FLAGS_addr;
  if (!addrArg.empty()) {
    folly::SocketAddress socketAddress;
    socketAddress.setFromHostPort(addrArg);
    host = socketAddress.getAddressStr();
    port = socketAddress.getPort();
  }

  const auto& serverCertPath =
      !FLAGS_cert.empty() ? FLAGS_cert : FLAGS_server_cert_path;
  const auto& serverKeyPath =
      !FLAGS_key.empty() ? FLAGS_key : FLAGS_server_key_path;
  const auto& transferRoot =
      !FLAGS_root.empty() ? FLAGS_root : FLAGS_transfer_root;
  auto congestionControlName = !FLAGS_cc_algorithm.empty()
      ? FLAGS_cc_algorithm
      : FLAGS_congestion_control;
  if (congestionControlName == "reno") {
    congestionControlName = "newreno";
  }
  auto congestionControl =
      quic::congestionControlStrToType(congestionControlName);
  if (!congestionControl.has_value()) {
    MVLOG_ERROR << "Unknown congestion control: " << congestionControlName;
    return -3;
  }

  if (FLAGS_mode == "server") {
    if (FLAGS_connect_only) {
      MVLOG_ERROR << "connect_only is not supported in server mode";
      return -1;
    }
    if (serverCertPath.empty() != serverKeyPath.empty()) {
      MVLOG_ERROR
          << "Both certificate and key paths must be provided together";
      return -4;
    }
    EchoServer server(
        std::move(alpns),
        host,
        port,
        FLAGS_use_datagrams,
        FLAGS_active_conn_id_limit,
        FLAGS_enable_migration,
        serverCertPath,
        serverKeyPath,
        transferRoot,
        FLAGS_qlog_dir,
        FLAGS_response_bytes,
        congestionControl.value());
    server.start();
  } else if (FLAGS_mode == "transport-server") {
    EchoTransportServer server(host, port);
    server.start();
  } else if (FLAGS_mode == "client") {
    if (host.empty() || port == 0) {
      MVLOG_ERROR << "EchoClient expected --host and --port";
      return -2;
    }
    EchoClient client(
        host,
        port,
        FLAGS_use_datagrams,
        FLAGS_active_conn_id_limit,
        FLAGS_enable_migration,
        std::move(alpns),
        FLAGS_connect_only,
        FLAGS_client_cert_path,
        FLAGS_client_key_path);
    auto res = client.start(FLAGS_token);
    return res.hasError() ? EXIT_FAILURE : EXIT_SUCCESS;
  } else {
    MVLOG_ERROR << "Unknown mode specified: " << FLAGS_mode;
    return -1;
  }
  return 0;
}
