#include <iostream>
#include <httplib.h>
#include <openssl/hmac.h>

std::string b2a_hex(const std::uint8_t* p, std::size_t n);
std::string hmac_sha256(const char* key, std::size_t klen, const char* data, std::size_t dlen);

std::string generate_signature(const std::string& type, const std::string& res);

void launch_and_patch();

std::string enckey = "unset";
const std::string secret = "6874394dee7ff1b785b8f612f58369069b7b7f837104262e2d9e48c4d4053a9c";
const std::string version_hash = "c926e2f8fa5c5db80f7f64811c2a790f30d7b6906a175d1d1113e78d3700ccd5f5122afe14364068815073bb251cd58efc47e31d3ab5d40f7ca75f118613dec712a05fc0fce3b386098029754d422b19b824a6e78d0124011ecc6890633cd52d4bef2d04742f8962133ae3c427630913";


int main() {
    launch_and_patch();

    httplib::SSLServer svr("./keyauth.win+2.pem", "./keyauth.win+2-key.pem");

    svr.Post("/api/1.2/", [&svr](const auto& req, auto& res) {
        const auto& req_type = req.get_param_value("type");

        if (req_type == "init") {
            enckey = req.get_param_value("enckey");
            res.body = R"({"success": true, "message": "Initialized", "sessionid": "carterno", "appinfo": { "numUsers" : "", "numOnlineUsers": "", "numKeys": "", "version": "0.0", "customerPanelLink": "" }, "newSession": true, "nonce": "baalechigale"})";
            std::cout << "[+] Faked initialisation request\n";
        }

        if (req_type == "checkblacklist") {
            res.body = R"({"success": false, "message": "Client is not blacklisted", "nonce": "baalechigale"})";
            std::cout << "[+] Passed blacklist check\n";
        }

        if (req_type == "login") {
            res.body = R"({"success": true, "message": "Logged in!", "info": { "username": "brandon crack", "subscriptions": [ {"subscription": "stopwatch", "key": null, "expiry": "1718694857", "timeleft": 999999995 } ], "ip": "1.1.1.1", "hwid": ")" + req.get_param_value("hwid") + R"(", "createdate": "12345", "lastlogin": "12345"}, "nonce": "baalechigale"})";
            std::cout << "[+] Logged in\n";
        }

        if (req_type == "check") {
            res.body = R"({"success": false, "message": "Session is not validated", "nonce": "baalechigale"})";
        }

        if (req_type == "logout") {
            svr.stop();
        }

        res.set_header("signature", generate_signature(req_type, res.body));
    });

    svr.Get("/f1Lthz4/3082b26d4dd420e9e8bf00bdbd36cb9c", [](const auto& req, auto& res) {
       res.set_content(version_hash, "application/text");
    });

    svr.Get("/u/win-x64_2.zip", [](const auto& req, auto& res) {
        std::string out;
        httplib::detail::read_file("./win-x64_2.zip", out);
        res.set_content(out, "application/zip");
    });

    svr.set_post_routing_handler([](const auto& req, auto& res) {
       std::cout << req.path << '\n';
    });

    svr.listen("127.0.0.1", 443);
    return 0;
}

void launch_and_patch() {
    PROCESS_INFORMATION process_information;
    STARTUPINFOA startupinfo;
    ZeroMemory(&startupinfo, sizeof(STARTUPINFOA));
    CreateProcessA(R"(./Stopwatch.exe)", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startupinfo, &process_information);

    const char* carter = "./patcher.dll";
    auto offset = VirtualAllocEx(process_information.hProcess, nullptr, strlen(carter), MEM_COMMIT, PAGE_READWRITE);

    WriteProcessMemory(process_information.hProcess, offset, carter, strlen(carter), nullptr);

    auto loadlib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    CreateRemoteThread(process_information.hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)loadlib, offset, NULL, nullptr);

    ResumeThread(process_information.hThread);
}

std::string generate_signature(const std::string& type, const std::string& res) {
    std::string key;

    if (type == "init") {
        key = secret;
    } else {
        key = enckey + "-" + secret;
    }

    return hmac_sha256(key.c_str(), key.size(), res.c_str(), res.size());
}

// pasted from stack overflow below

std::string b2a_hex(const std::uint8_t* p, std::size_t n) {
    static const char hex[] = "0123456789abcdef";
    std::string res;
    res.reserve(n * 2);

    for (auto end = p + n; p != end; ++p) {
        const std::uint8_t v = (*p);
        res += hex[(v >> 4) & 0x0F];
        res += hex[v & 0x0F];
    }

    return res;
}

std::string hmac_sha256(const char* key, std::size_t klen, const char* data, std::size_t dlen) {
    std::uint8_t digest[EVP_MAX_MD_SIZE];
    std::uint32_t dilen{};

    auto p = HMAC(
            EVP_sha256()
            , key
            , klen
            , (std::uint8_t*)data
            , dlen
            , digest
            , &dilen
    );
    assert(p);

    return b2a_hex(digest, dilen);
}
