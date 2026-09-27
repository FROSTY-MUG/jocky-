#include "agent.hpp"
#include "consent.hpp"
#include "module_loader.hpp"
#include "collectors/process.hpp"
#include "collectors/network.hpp"
#include "collectors/driver.hpp"
#include "detect/byovd.hpp"
#include "detect/inject.hpp"
#include "output.hpp"
#include "errors.hpp"
#include <iostream>
#include <string>
#include <fstream>
#include <cstdlib>
#include <windows.h>

namespace jocky {

void write_audit_log(const std::string& msg) {
    std::string audit_dir;
    const char* pd = std::getenv("ProgramData");
    if (pd) {
        audit_dir = std::string(pd) + "\\JOCKY";
    } else {
        audit_dir = "C:\\ProgramData\\JOCKY";
    }
    CreateDirectoryA(audit_dir.c_str(), NULL);
    std::ofstream audit(audit_dir + "\\audit.log", std::ios::app);
    if (audit.is_open()) {
        audit << msg << std::endl;
    }
}

int Agent::run(int argc, char* argv[]) {
    if (argc < 2) return 1;

    std::string cmd = argv[1];

    if (cmd == "--version") {
        std::cout << JOCKY_AGENT_NAME << " version " << JOCKY_AGENT_VERSION << std::endl;
        return 0;
    }

    if (cmd == "consent-check") {
        try {
            ConsentValidator::verify_from_env();
            return 0;
        } catch (const ConsentError& e) {
            write_audit_log("Consent validation failed: " + std::string(e.what()));
            std::cerr << e.what() << std::endl;
            return 1;
        } catch (...) {
            return 1;
        }
    }

    if (cmd == "collect") {
        if (argc < 4 || (std::string(argv[2]) != "--mode" && std::string(argv[2]) != "-m")) return 3;
        std::string mode = argv[3];
        try {
            const char* token_env = std::getenv("JOCKY_CONSENT_TOKEN");
            if (token_env) {
                ConsentValidator::verify_from_env();
            }
            nlohmann::json res;
            if (mode == "processes" || mode == "process") res = ProcessCollector::collect();
            else if (mode == "network") res = NetworkCollector::collect();
            else if (mode == "drivers" || mode == "driver") res = DriverCollector::collect();
            else return 3;

            print_json(res);
            return 0;
        } catch (const ConsentError& e) {
            write_audit_log("Consent validation failed: " + std::string(e.what()));
            std::cerr << e.what() << std::endl;
            return 1;
        } catch (const std::exception& e) {
            std::cerr << "Collection Error: " << e.what() << std::endl;
            return 3;
        }
    }

    if (cmd == "detect") {
        if (argc < 4 || (std::string(argv[2]) != "--mode" && std::string(argv[2]) != "--rule" && std::string(argv[2]) != "-r")) return 4;
        std::string mode = argv[3];
        try {
            const char* token_env = std::getenv("JOCKY_CONSENT_TOKEN");
            if (token_env) {
                ConsentValidator::verify_from_env();
            }
            std::vector<Finding> res;
            if (mode == "byovd") res = ByovdDetector::detect();
            else if (mode == "inject") {
                int duration = 30;
                for (int i = 4; i < argc; ++i) {
                    if (std::string(argv[i]) == "--duration" && i + 1 < argc) {
                        duration = std::stoi(argv[i + 1]);
                        break;
                    }
                }
                res = InjectDetector::detect(duration);
            } else return 4;

            nlohmann::json j = nlohmann::json::array();
            for (const auto& f : res) {
                nlohmann::json f_j;
                to_json(f_j, f);
                j.push_back(f_j);
            }
            print_json(j);
            return 0;
        } catch (const ConsentError& e) {
            write_audit_log("Consent validation failed: " + std::string(e.what()));
            std::cerr << e.what() << std::endl;
            return 1;
        } catch (const std::exception& e) {
            std::cerr << "Detection Error: " << e.what() << std::endl;
            return 4;
        }
    }

    if (cmd == "run") {
        std::string path;
        std::string pubkey_arg;
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--module" && i + 1 < argc) {
                path = argv[++i];
            } else if (arg == "--pubkey" && i + 1 < argc) {
                pubkey_arg = argv[++i];
            } else if (arg[0] != '-' && path.empty()) {
                path = arg;
            }
        }
        if (path.empty()) return 2;
        try {
            const char* token_env = std::getenv("JOCKY_CONSENT_TOKEN");
            if (token_env) {
                ConsentValidator::verify_from_env();
            }
            std::string pubkey_str;
            const char* pubkey_env = std::getenv("JOCKY_MANAGER_PUBKEY");
            if (pubkey_env) {
                pubkey_str = pubkey_env;
            } else if (!pubkey_arg.empty()) {
                std::ifstream pkf(pubkey_arg);
                if (pkf.is_open()) {
                    pubkey_str = std::string((std::istreambuf_iterator<char>(pkf)), std::istreambuf_iterator<char>());
                } else {
                    pubkey_str = pubkey_arg;
                }
            }
            if (pubkey_str.empty()) throw ConsentError("Missing pubkey (provide via JOCKY_MANAGER_PUBKEY or --pubkey)");
            int res = ModuleLoader::load_and_run(path, pubkey_str);
            std::cout << res << std::endl;
            return 0;
        } catch (const ConsentError& e) {
            write_audit_log("Consent validation failed: " + std::string(e.what()));
            std::cerr << e.what() << std::endl;
            return 1;
        } catch (const std::exception& e) {
            std::cerr << "Module Loader Error: " << e.what() << std::endl;
            return 2;
        }
    }

    return 1;
}

} // namespace jocky
