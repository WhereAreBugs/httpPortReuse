#include <iostream>
#include <memory>
#include <vector>
#include <string>
#include <string_view>
#include <array>
#include <boost/asio.hpp>
#include <thread>

namespace asio = boost::asio;
using boost::asio::ip::tcp;

const unsigned short LISTEN_PORT = 8888;
const unsigned short HTTP_HTTPS_TARGET_PORT = 8892;
const unsigned short UNKNOWN_TARGET_PORT = 8891;
const std::string TARGET_HOST = "127.0.0.1";

bool is_tls_handshake(const char* data, std::size_t length) {
    if (length < 3) return false;
    return data[0] == 0x16 && data[1] == 0x03;
}
bool is_http_request(const char* data, std::size_t length) {
    if (length == 0) return false;
    static const std::array<std::string_view, 9> methods = {
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
        "OPTIONS ", "CONNECT ", "TRACE ", "PATCH "
    };
    std::string_view request_data(data, length);
    for (const auto& method : methods) {
        if (request_data.rfind(method, 0) == 0) {
            return true;
        }
    }
    return false;
}

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket client_socket)
        : client_socket_(std::move(client_socket)),
          target_socket_(client_socket_.get_executor()),
          client_buffer_{},
          target_buffer_{}
          {}

    void start() {
        do_peek();
    }

private:
    void do_peek() {
        peek_buffer_.resize(64);
        client_socket_.async_read_some(asio::buffer(peek_buffer_),
            [self = shared_from_this()](const boost::system::error_code& ec, std::size_t length) {
                self->on_peek(ec, length);
            });
    }

    void on_peek(const boost::system::error_code& ec, std::size_t length) {
        if (ec) { if (ec != asio::error::eof) std::cerr << "Peek error: " << ec.message() << std::endl; return; }

        peek_data_size_ = length;
        unsigned short target_port;
        std::string type_str;

        const char* data = peek_buffer_.data();
        if (is_tls_handshake(data, length)) {
            target_port = HTTP_HTTPS_TARGET_PORT;
            type_str = "HTTPS/TLS";
        } else if (is_http_request(data, length)) {
            target_port = HTTP_HTTPS_TARGET_PORT;
            type_str = "HTTP";
        } else {
            target_port = UNKNOWN_TARGET_PORT;
            type_str = "Unknown";
        }

        std::cout << "New connection from " << client_socket_.remote_endpoint()
                  << ". Detected as " << type_str << ". Forwarding to " << TARGET_HOST << ":" << target_port << std::endl;

        auto resolver = std::make_shared<tcp::resolver>(client_socket_.get_executor());
        resolver->async_resolve(TARGET_HOST, std::to_string(target_port),
            [this, self = shared_from_this(), resolver]
            (const boost::system::error_code& ec, const tcp::resolver::results_type& endpoints) {
                (void)resolver;
                if (!ec) {
                    connect_to_target(endpoints);
                } else {
                    std::cerr << "Resolve error: " << ec.message() << std::endl;
                    close_sockets(ec);
                }
            });
    }

    void connect_to_target(const tcp::resolver::results_type& endpoints) {
        asio::async_connect(target_socket_, endpoints,
            [self = shared_from_this()](const boost::system::error_code& ec, const tcp::endpoint& /*endpoint*/) {
                self->on_connect(ec);
            });
    }

    void on_connect(const boost::system::error_code& ec) {
        if (ec) { std::cerr << "Connect error: " << ec.message() << std::endl; close_sockets(ec); return; }

        asio::async_write(target_socket_, asio::buffer(peek_buffer_, peek_data_size_),
            [self = shared_from_this()](const boost::system::error_code& ec, std::size_t /*length*/) {
                if (!ec) {
                    self->do_read_from_client();
                    self->do_read_from_target();
                } else {
                    std::cerr << "Initial write to target failed: " << ec.message() << std::endl;
                    self->close_sockets(ec);
                }
            });
    }

    void do_read_from_client() {
        client_socket_.async_read_some(asio::buffer(client_buffer_), [self = shared_from_this()](const boost::system::error_code& ec, std::size_t length) {
            if (!ec) { self->do_write_to_target(length); } else { self->close_sockets(ec); }
        });
    }
    void do_write_to_target(std::size_t length) {
        asio::async_write(target_socket_, asio::buffer(client_buffer_, length), [self = shared_from_this()](const boost::system::error_code& ec, std::size_t /*length*/) {
            if (!ec) { self->do_read_from_client(); } else { self->close_sockets(ec); }
        });
    }
    void do_read_from_target() {
        target_socket_.async_read_some(asio::buffer(target_buffer_), [self = shared_from_this()](const boost::system::error_code& ec, std::size_t length) {
            if (!ec) { self->do_write_to_client(length); } else { self->close_sockets(ec); }
        });
    }
    void do_write_to_client(std::size_t length) {
        asio::async_write(client_socket_, asio::buffer(target_buffer_, length), [self = shared_from_this()](const boost::system::error_code& ec, std::size_t /*length*/) {
            if (!ec) { self->do_read_from_target(); } else { self->close_sockets(ec); }
        });
    }
    void close_sockets(const boost::system::error_code& ec) {
        if (ec && ec != asio::error::eof) { std::cerr << "Closing sockets due to error: " << ec.message() << std::endl; }
        if (client_socket_.is_open()) { boost::system::error_code ignored_ec; client_socket_.shutdown(tcp::socket::shutdown_both, ignored_ec); client_socket_.close(ignored_ec); }
        if (target_socket_.is_open()) { boost::system::error_code ignored_ec; target_socket_.shutdown(tcp::socket::shutdown_both, ignored_ec); target_socket_.close(ignored_ec); }
    }

    tcp::socket client_socket_;
    tcp::socket target_socket_;
    std::vector<char> peek_buffer_;
    std::size_t peek_data_size_ = 0;
    std::array<char, 4096> client_buffer_;
    std::array<char, 4096> target_buffer_;
};

class Server {
public:
    Server(asio::io_context& io_context, unsigned short port)
        : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)) {
        std::cout << "Dispatcher listening on port " << port << "..." << std::endl;
        std::cout << "Forwarding HTTP/HTTPS to " << TARGET_HOST << ":" << HTTP_HTTPS_TARGET_PORT << std::endl;
        std::cout << "Forwarding others to " << TARGET_HOST << ":" << UNKNOWN_TARGET_PORT << std::endl;
        do_accept();
    }

private:
    void do_accept() {
        acceptor_.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    std::make_shared<Session>(std::move(socket))->start();
                } else {
                    std::cerr << "Accept error: " << ec.message() << std::endl;
                }
                do_accept();
            });
    }

    tcp::acceptor acceptor_;
};

int main() {
    try {
        asio::io_context io_context;
        Server s(io_context, LISTEN_PORT);

        std::cout << "Starting worker thread." << std::endl;
        io_context.run();

    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
    return 0;
}