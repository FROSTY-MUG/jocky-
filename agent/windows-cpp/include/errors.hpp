#pragma once

#include <stdexcept>
#include <string>

namespace jocky {

class AgentError : public std::runtime_error {
public:
    explicit AgentError(const std::string& msg) : std::runtime_error(msg) {}
};

class ConsentError : public AgentError {
public:
    explicit ConsentError(const std::string& msg) : AgentError(msg) {}
};

class ModuleLoadError : public AgentError {
public:
    explicit ModuleLoadError(const std::string& msg) : AgentError(msg) {}
};

class CollectionError : public AgentError {
public:
    explicit CollectionError(const std::string& msg) : AgentError(msg) {}
};

class DetectionError : public AgentError {
public:
    explicit DetectionError(const std::string& msg) : AgentError(msg) {}
};

} // namespace jocky
