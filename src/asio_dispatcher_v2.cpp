/**
 * @file tcp_proxy.cpp
 * @brief An intelligent asynchronous TCP proxy with per-target PROXY protocol v2 support.
 *
 * This program listens on a specified port, inspects the initial data from a new
 * connection, and forwards the traffic to a pre-configured target. The decision to
 * inject a HAProxy PROXY protocol v2 header is made on a per-target basis, allowing
 * flexible routing to backends that may or may not support the protocol.
 */

#include <iostream>
#include <memory>
#include <vector>
#include <string>
#include <string_view>
#include <array>
#include <thread>

#include <boost/asio.hpp>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

namespace tcp_proxy {

namespace asio = boost::asio;
using boost::asio::ip::tcp;

/**
 * @struct Target
 * @brief Encapsulates all configuration for a forwarding target.
 */
struct Target {
    std::string host;
    unsigned short port;
    bool use_proxy_protocol;
};

constexpr unsigned short kListenPort = 8888;

const Target kHttpHttpsTarget = {"127.0.0.1", 443, false};

const Target kUnknownTarget = {"127.0.0.1", 22, false};



// --- Buffer and Protocol Constants ---
constexpr std::size_t kPeekBufferSize = 64;
constexpr std::size_t kDataBufferSize = 4096;
constexpr unsigned char kTLSHandshake = 0x16;
constexpr unsigned char kTLSVersionMajor = 0x03;
constexpr unsigned char kProxyV2VersionAndCommand = 0x21;
constexpr unsigned char kProxyV2FamilyProtocolTCPv4 = 0x11;
constexpr unsigned char kProxyV2FamilyProtocolTCPv6 = 0x21;
constexpr size_t kProxyV2IPv4AddrLen = sizeof(asio::ip::address_v4::bytes_type) * 2 + sizeof(uint16_t) * 2;
constexpr size_t kProxyV2IPv6AddrLen = sizeof(asio::ip::address_v6::bytes_type) * 2 + sizeof(uint16_t) * 2;

std::vector<char> generate_proxy_protocol_v2_header(
    const tcp::endpoint& client_endpoint,
    const tcp::endpoint& server_endpoint)
{
    static const std::array<char, 12> kProxyV2Signature = {
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
    };
    std::vector<char> header;
    header.reserve(16 + kProxyV2IPv6AddrLen);
    header.insert(header.end(), kProxyV2Signature.begin(), kProxyV2Signature.end());
    header.push_back(kProxyV2VersionAndCommand);
    auto append_bytes = [&](const auto& value) {
        const char* bytes = reinterpret_cast<const char*>(&value);
        header.insert(header.end(), bytes, bytes + sizeof(value));
    };
    if (client_endpoint.protocol() == tcp::v4()) {
        header.push_back(kProxyV2FamilyProtocolTCPv4);
        uint16_t len_net = htons(static_cast<uint16_t>(kProxyV2IPv4AddrLen));
        append_bytes(len_net);
        append_bytes(client_endpoint.address().to_v4().to_bytes());
        append_bytes(server_endpoint.address().to_v4().to_bytes());
        append_bytes(htons(client_endpoint.port()));
        append_bytes(htons(server_endpoint.port()));
    } else {
        header.push_back(kProxyV2FamilyProtocolTCPv6);
        uint16_t len_net = htons(static_cast<uint16_t>(kProxyV2IPv6AddrLen));
        append_bytes(len_net);
        append_bytes(client_endpoint.address().to_v6().to_bytes());
        append_bytes(server_endpoint.address().to_v6().to_bytes());
        append_bytes(htons(client_endpoint.port()));
        append_bytes(htons(server_endpoint.port()));
    }
    return header;
}
bool is_tls_handshake(const char* data, std::size_t length) {
    if (length < 3) return false;
    return static_cast<unsigned char>(data[0]) == kTLSHandshake &&
           static_cast<unsigned char>(data[1]) == kTLSVersionMajor;
}
bool is_http_request(const char* data, std::size_t length) {
    if (length == 0) return false;
    static const std::array<std::string_view, 9> kHttpMethods = {
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
        "OPTIONS ", "CONNECT ", "TRACE ", "PATCH "
    };
    std::string_view request_data(data, length);
    for (const auto& method : kHttpMethods) {
        if (request_data.rfind(method, 0) == 0) {
            return true;
        }
    }
    return false;
}


using SharedStrand = asio::strand<asio::any_io_executor>;

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket client_socket, tcp::endpoint local_endpoint, SharedStrand& strand)
        : client_socket_(std::move(client_socket)),
          target_socket_(client_socket_.get_executor()),
          local_endpoint_(local_endpoint),
          strand_(strand),
          client_buffer_{},
          target_buffer_{}
    {
        boost::system::error_code ec;
        remote_endpoint_str_ = client_socket_.remote_endpoint(ec).address().to_string();
    }

    void start() {
        do_peek();
    }

private:
    void do_peek() {
        peek_buffer_.resize(kPeekBufferSize);
        client_socket_.async_read_some(asio::buffer(peek_buffer_),
            asio::bind_executor(strand_, [self = shared_from_this()](auto ec, auto len) {
                self->on_peek(ec, len);
            }));
    }

    void on_peek(const boost::system::error_code& ec, std::size_t length) {
        if (ec) {
            if (ec != asio::error::eof) std::cerr << "Peek error from " << remote_endpoint_str_ << ": " << ec.message() << std::endl;
            return;
        }

        peek_data_size_ = length;
        std::string type_str;

        const char* data = peek_buffer_.data();
        if (is_tls_handshake(data, length)) {
            selected_target_ = kHttpHttpsTarget;
            type_str = "HTTPS/TLS";
        } else if (is_http_request(data, length)) {
            selected_target_ = kHttpHttpsTarget;
            type_str = "HTTP";
        } else {
            selected_target_ = kUnknownTarget;
            type_str = "Unknown";
        }

        std::cout << "New connection from " << remote_endpoint_str_
                  << ". Detected as " << type_str << ". Forwarding to "
                  << selected_target_.host << ":" << selected_target_.port << std::endl;

        auto resolver = std::make_shared<tcp::resolver>(strand_);
        resolver->async_resolve(selected_target_.host, std::to_string(selected_target_.port),
            asio::bind_executor(strand_,
                [this, self = shared_from_this(), resolver]
                (const auto& ec, const auto& endpoints) {
                    if (!ec) {
                        connect_to_target(endpoints);
                    } else {
                        std::cerr << "Resolve error for " << selected_target_.host << ": " << ec.message() << std::endl;
                        close_sockets(ec);
                    }
                }));
    }

    void connect_to_target(const tcp::resolver::results_type& endpoints) {
        asio::async_connect(target_socket_, endpoints,
            asio::bind_executor(strand_, [self = shared_from_this()](auto ec, auto /*ep*/) {
                self->on_connect(ec);
            }));
    }

    void on_connect(const boost::system::error_code& ec) {
        if (ec) {
            std::cerr << "Connect error to target " << selected_target_.host << ":" << selected_target_.port << ": " << ec.message() << std::endl;
            close_sockets(ec);
            return;
        }

        std::vector<asio::const_buffer> buffers_to_send;

        if (selected_target_.use_proxy_protocol) {
            std::cout << "Injecting PROXY protocol v2 header for " << remote_endpoint_str_
                      << " to " << selected_target_.host << std::endl;
            proxy_header_ = generate_proxy_protocol_v2_header(client_socket_.remote_endpoint(), local_endpoint_);
            buffers_to_send.push_back(asio::buffer(proxy_header_));
        }

        buffers_to_send.push_back(asio::buffer(peek_buffer_.data(), peek_data_size_));

        asio::async_write(target_socket_, buffers_to_send,
            asio::bind_executor(strand_, [self = shared_from_this()](auto ec, auto /*len*/) {
                if (!ec) {
                    self->do_read_from_client();
                    self->do_read_from_target();
                } else {
                    std::cerr << "Initial write to target failed: " << ec.message() << std::endl;
                    self->close_sockets(ec);
                }
            }));
    }

    void do_read_from_client() {
        client_socket_.async_read_some(asio::buffer(client_buffer_),
            asio::bind_executor(strand_, [self = shared_from_this()](auto ec, auto len) {
                if (!ec) { self->do_write_to_target(len); } else { self->close_sockets(ec); }
            }));
    }
    void do_write_to_target(std::size_t length) {
        asio::async_write(target_socket_, asio::buffer(client_buffer_, length),
            asio::bind_executor(strand_, [self = shared_from_this()](auto ec, auto /*len*/) {
                if (!ec) { self->do_read_from_client(); } else { self->close_sockets(ec); }
            }));
    }
    void do_read_from_target() {
        target_socket_.async_read_some(asio::buffer(target_buffer_),
            asio::bind_executor(strand_, [self = shared_from_this()](auto ec, auto len) {
                if (!ec) { self->do_write_to_client(len); } else { self->close_sockets(ec); }
            }));
    }
    void do_write_to_client(std::size_t length) {
        asio::async_write(client_socket_, asio::buffer(target_buffer_, length),
            asio::bind_executor(strand_, [self = shared_from_this()](auto ec, auto /*len*/) {
                if (!ec) { self->do_read_from_target(); } else { self->close_sockets(ec); }
            }));
    }
    void close_sockets(const boost::system::error_code& ec) {
        if (ec && ec != asio::error::eof) {
            std::cerr << "Closing session for " << remote_endpoint_str_ << " due to error: " << ec.message() << std::endl;
        }
        boost::system::error_code ignored_ec;
        if (client_socket_.is_open()) {
            client_socket_.shutdown(tcp::socket::shutdown_both, ignored_ec);
            client_socket_.close(ignored_ec);
        }
        if (target_socket_.is_open()) {
            target_socket_.shutdown(tcp::socket::shutdown_both, ignored_ec);
            target_socket_.close(ignored_ec);
        }
    }


    Target selected_target_;

    tcp::socket client_socket_;
    tcp::socket target_socket_;
    tcp::endpoint local_endpoint_;
    SharedStrand& strand_;
    std::string remote_endpoint_str_;

    std::vector<char> peek_buffer_;
    std::size_t peek_data_size_ = 0;
    std::vector<char> proxy_header_;

    std::array<char, kDataBufferSize> client_buffer_;
    std::array<char, kDataBufferSize> target_buffer_;
};

class Server {
public:
    Server(asio::io_context& io_context, unsigned short port)
        : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)),
          strand_(asio::make_strand(io_context))
    {
        std::cout << "Dispatcher listening on port " << port << "..." << std::endl;
        std::cout << "Forwarding HTTP/HTTPS to " << kHttpHttpsTarget.host << ":" << kHttpHttpsTarget.port
                  << " (PROXY protocol: " << (kHttpHttpsTarget.use_proxy_protocol ? "on" : "off") << ")" << std::endl;
        std::cout << "Forwarding others to " << kUnknownTarget.host << ":" << kUnknownTarget.port
                  << " (PROXY protocol: " << (kUnknownTarget.use_proxy_protocol ? "on" : "off") << ")" << std::endl;
        do_accept();
    }

private:
    void do_accept() {
        acceptor_.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    boost::system::error_code endpoint_ec;
                    tcp::endpoint local_endpoint = socket.local_endpoint(endpoint_ec);
                    if (!endpoint_ec) {
                        std::make_shared<Session>(std::move(socket), local_endpoint, strand_)->start();
                    } else {
                         std::cerr << "Failed to get local endpoint: " << endpoint_ec.message() << std::endl;
                    }
                } else {
                    std::cerr << "Accept error: " << ec.message() << std::endl;
                }
                do_accept();
            });
    }

    tcp::acceptor acceptor_;
    SharedStrand strand_;
};

} // namespace tcp_proxy

int main() {
    try {
        boost::asio::io_context io_context;
        tcp_proxy::Server server(io_context, tcp_proxy::kListenPort);

        std::vector<std::thread> threads;
        const auto num_threads = std::max(2u, std::thread::hardware_concurrency());

        std::cout << "Starting " << num_threads << " worker threads." << std::endl;
        threads.reserve(num_threads);
        for (unsigned int i = 0; i < num_threads; ++i) {
            threads.emplace_back([&io_context]() {
                io_context.run();
            });
        }

        for (auto& t : threads) {
            if (t.joinable()) {
                t.join();
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Fatal Exception: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}