#pragma once

#include <iostream>
#include <map>
#include <string>
#include <functional>
#include <vector>
#include <sstream>
#include <fstream>
#include <filesystem>

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "Ws2_32.lib")
#else
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
#  include <arpa/inet.h>
#endif

namespace httplib {

struct Request {
    std::string method;
    std::string path;
    std::string body;
    std::map<std::string, std::string> params;

    std::string get_param_value(const std::string &name) const {
        auto it = params.find(name);
        return (it == params.end()) ? std::string() : it->second;
    }
};

struct Response {
    int status = 200;
    std::string body;
    std::map<std::string, std::string> headers;

    void set_header(const std::string &name, const std::string &value) {
        headers[name] = value;
    }

    void set_content(const std::string &body_, const std::string &content_type) {
        body = body_;
        set_header("Content-Type", content_type);
    }
};

using Handler = std::function<void(const Request &, Response &)>;

class Server {
public:
    Server() {
#if defined(_WIN32)
        WSADATA wsa_data;
        WSAStartup(MAKEWORD(2, 2), &wsa_data);
#endif
    }

    ~Server() {
#if defined(_WIN32)
        WSACleanup();
#endif
    }

    bool Get(const std::string &path, Handler handler) {
        handlers_[path] = std::move(handler);
        return true;
    }

    void set_mount_point(const std::string &mount_point, const std::string &directory) {
        mount_point_ = mount_point;
        static_dir_ = directory;
    }

    bool listen(const std::string &host, int port) {
        int server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) return false;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr(host.c_str());
        addr.sin_port = htons(port);

        if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) return false;
        if (::listen(server_fd, 5) < 0) return false;

        std::cout << "Server running on " << host << ":" << port << "\n";

        while (true) {
            sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_fd = accept(server_fd, (sockaddr*)&client_addr, &client_len);
            if (client_fd < 0) continue;

            handle_client(client_fd);
#if defined(_WIN32)
            closesocket(client_fd);
#else
            close(client_fd);
#endif
        }
        return true;
    }

private:
    void handle_client(int client_fd) {
        char buffer[4096];
        int bytes = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) return;
        buffer[bytes] = '\0';

        std::string req_str(buffer);

        // Simple parsing
        Request req;
        std::istringstream iss(req_str);
        iss >> req.method >> req.path;

        // Parse query params
        size_t qpos = req.path.find('?');
        if (qpos != std::string::npos) {
            std::string query = req.path.substr(qpos + 1);
            req.path = req.path.substr(0, qpos);
            parse_query_params(query, req.params);
        }

        Response res;

        auto it = handlers_.find(req.path);
        if (it != handlers_.end()) {
            it->second(req, res);
        } else {
            serve_static(req.path, res);
        }

        // Build response
        std::ostringstream oss;
        oss << "HTTP/1.1 " << res.status << " OK\r\n";
        for (auto &h : res.headers) {
            oss << h.first << ": " << h.second << "\r\n";
        }
        oss << "Content-Length: " << res.body.size() << "\r\n\r\n";
        oss << res.body;

        std::string response = oss.str();
        send(client_fd, response.c_str(), (int)response.size(), 0);
    }

    void parse_query_params(const std::string &query, std::map<std::string, std::string> &params) {
        std::string key, value;
        size_t pos = 0;
        while (pos < query.size()) {
            size_t eq = query.find('=', pos);
            if (eq == std::string::npos) break;
            key = query.substr(pos, eq - pos);
            size_t amp = query.find('&', eq);
            value = (amp == std::string::npos) ? query.substr(eq + 1) : query.substr(eq + 1, amp - eq - 1);
            params[key] = value;
            if (amp == std::string::npos) break;
            pos = amp + 1;
        }
    }

    void serve_static(const std::string &path, Response &res) {
        std::filesystem::path local = static_dir_;
        std::string p = path;
        if (p == "/") p = "/index.html";
        local /= p.substr(1);

        if (!std::filesystem::exists(local) || std::filesystem::is_directory(local)) {
            res.status = 404;
            res.set_content("Not Found", "text/plain");
            return;
        }

        std::ifstream file(local, std::ios::binary);
        if (!file) {
            res.status = 500;
            res.set_content("Cannot open file", "text/plain");
            return;
        }

        std::ostringstream ss;
        ss << file.rdbuf();
        res.body = ss.str();
        res.status = 200;
        res.set_header("Content-Type", content_type(local.string()));
    }

  
    std::string content_type(const std::string &path) {
        auto ends_with = [](const std::string &str, const std::string &suffix) {
            return str.size() >= suffix.size() && str.substr(str.size() - suffix.size()) == suffix;
        };
        if (ends_with(path, ".html")) return "text/html";
        if (ends_with(path, ".css")) return "text/css";
        if (ends_with(path, ".js")) return "application/javascript";
        if (ends_with(path, ".json")) return "application/json";
        if (ends_with(path, ".png")) return "image/png";
        if (ends_with(path, ".jpg") || ends_with(path, ".jpeg")) return "image/jpeg";
        if (ends_with(path, ".svg")) return "image/svg+xml";
        return "application/octet-stream";
    }

private:
    std::map<std::string, Handler> handlers_;
    std::string mount_point_;
    std::string static_dir_;
};

} // namespace httplib