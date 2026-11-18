// SPDX-License-Identifier: AGPL-3.0-only
#include "callgraph/static_graph_json.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <string>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#include "callgraph/static_graph_join.h"

namespace callgraph {

namespace {

constexpr int kMaxDepth = 64;

class Parser {
public:
    explicit Parser(const std::string& text) : text_(text) {}

    bool parse(StaticGraphDocument* document)
    {
        skip_ws();
        if (!parse_document(document))
            return false;
        skip_ws();
        if (pos_ != text_.size())
            return fail("trailing data after the top-level object");
        return true;
    }

    const std::string& reason() const { return reason_; }

private:
    bool fail(const std::string& message)
    {
        if (reason_.empty())
            reason_ = message + " at byte " + std::to_string(pos_);
        return false;
    }

    void skip_ws()
    {
        while (pos_ < text_.size()) {
            const char c = text_[pos_];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
                ++pos_;
            else
                break;
        }
    }

    bool consume(char expected)
    {
        skip_ws();
        if (pos_ >= text_.size() || text_[pos_] != expected)
            return false;
        ++pos_;
        return true;
    }

    bool expect(char expected)
    {
        if (!consume(expected)) {
            char buffer[32];
            snprintf(buffer, sizeof(buffer), "expected '%c'", expected);
            return fail(buffer);
        }
        return true;
    }

    bool parse_hex4(unsigned* value)
    {
        if (pos_ + 4 > text_.size())
            return fail("truncated \\u escape");
        unsigned result = 0;
        for (int i = 0; i < 4; ++i) {
            const char c = text_[pos_++];
            result <<= 4;
            if (c >= '0' && c <= '9')
                result |= static_cast<unsigned>(c - '0');
            else if (c >= 'a' && c <= 'f')
                result |= static_cast<unsigned>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F')
                result |= static_cast<unsigned>(c - 'A' + 10);
            else
                return fail("invalid \\u escape");
        }
        *value = result;
        return true;
    }

    static void append_utf8(std::string* out, unsigned codepoint)
    {
        if (codepoint <= 0x7f) {
            out->push_back(static_cast<char>(codepoint));
        } else if (codepoint <= 0x7ff) {
            out->push_back(static_cast<char>(0xc0 | (codepoint >> 6)));
            out->push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
        } else if (codepoint <= 0xffff) {
            out->push_back(static_cast<char>(0xe0 | (codepoint >> 12)));
            out->push_back(
                static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
            out->push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
        } else {
            out->push_back(static_cast<char>(0xf0 | (codepoint >> 18)));
            out->push_back(
                static_cast<char>(0x80 | ((codepoint >> 12) & 0x3f)));
            out->push_back(
                static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
            out->push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
        }
    }

    bool parse_string(std::string* value)
    {
        value->clear();
        skip_ws();
        if (pos_ >= text_.size() || text_[pos_] != '"')
            return fail("expected a string");
        ++pos_;
        while (pos_ < text_.size()) {
            const char c = text_[pos_++];
            if (c == '"')
                return true;
            if (c != '\\') {
                value->push_back(c);
                continue;
            }
            if (pos_ >= text_.size())
                return fail("truncated escape");
            const char escape = text_[pos_++];
            switch (escape) {
            case '"':
                value->push_back('"');
                break;
            case '\\':
                value->push_back('\\');
                break;
            case '/':
                value->push_back('/');
                break;
            case 'b':
                value->push_back('\b');
                break;
            case 'f':
                value->push_back('\f');
                break;
            case 'n':
                value->push_back('\n');
                break;
            case 'r':
                value->push_back('\r');
                break;
            case 't':
                value->push_back('\t');
                break;
            case 'u': {
                unsigned codepoint = 0;
                if (!parse_hex4(&codepoint))
                    return false;
                if (codepoint >= 0xd800 && codepoint <= 0xdbff) {
                    if (pos_ + 2 > text_.size() || text_[pos_] != '\\' ||
                        text_[pos_ + 1] != 'u')
                        return fail("unpaired surrogate");
                    pos_ += 2;
                    unsigned low = 0;
                    if (!parse_hex4(&low))
                        return false;
                    if (low < 0xdc00 || low > 0xdfff)
                        return fail("invalid low surrogate");
                    codepoint = 0x10000 + ((codepoint - 0xd800) << 10) +
                                (low - 0xdc00);
                }
                append_utf8(value, codepoint);
                break;
            }
            default:
                return fail("invalid escape");
            }
        }
        return fail("unterminated string");
    }

    bool parse_u64(uint64_t* value)
    {
        skip_ws();
        const size_t start = pos_;
        uint64_t result = 0;
        while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') {
            const uint64_t digit = static_cast<uint64_t>(text_[pos_] - '0');
            if (result > (UINT64_MAX - digit) / 10)
                return fail("integer out of range");
            result = result * 10 + digit;
            ++pos_;
        }
        if (pos_ == start)
            return fail("expected an integer");
        *value = result;
        return true;
    }

    bool parse_bool(bool* value)
    {
        skip_ws();
        if (text_.compare(pos_, 4, "true") == 0) {
            pos_ += 4;
            *value = true;
            return true;
        }
        if (text_.compare(pos_, 5, "false") == 0) {
            pos_ += 5;
            *value = false;
            return true;
        }
        return fail("expected a boolean");
    }

    bool skip_value(int depth = 0)
    {
        if (depth > kMaxDepth)
            return fail("nesting too deep");
        skip_ws();
        if (pos_ >= text_.size())
            return fail("unexpected end of input");

        const char c = text_[pos_];
        if (c == '"') {
            std::string ignored;
            return parse_string(&ignored);
        }
        if (c == 't' || c == 'f') {
            bool ignored = false;
            return parse_bool(&ignored);
        }
        if (c == 'n') {
            if (text_.compare(pos_, 4, "null") != 0)
                return fail("invalid literal");
            pos_ += 4;
            return true;
        }
        if (c == '-' || (c >= '0' && c <= '9')) {
            // Numbers are only skipped here; accept a JSON number loosely.
            const size_t start = pos_;
            if (text_[pos_] == '-')
                ++pos_;
            while (pos_ < text_.size()) {
                const char d = text_[pos_];
                if ((d >= '0' && d <= '9') || d == '.' || d == 'e' ||
                    d == 'E' || d == '+' || d == '-')
                    ++pos_;
                else
                    break;
            }
            if (pos_ == start)
                return fail("expected a number");
            return true;
        }
        if (c == '[') {
            ++pos_;
            skip_ws();
            if (consume(']'))
                return true;
            while (true) {
                if (!skip_value(depth + 1))
                    return false;
                skip_ws();
                if (consume(']'))
                    return true;
                if (!consume(','))
                    return fail("expected ',' or ']'");
            }
        }
        if (c == '{') {
            ++pos_;
            skip_ws();
            if (consume('}'))
                return true;
            while (true) {
                std::string key;
                if (!parse_string(&key))
                    return false;
                if (!expect(':'))
                    return false;
                if (!skip_value(depth + 1))
                    return false;
                skip_ws();
                if (consume('}'))
                    return true;
                if (!consume(','))
                    return fail("expected ',' or '}'");
            }
        }
        return fail("unexpected character");
    }

    bool parse_u64_array(std::vector<uint64_t>* values)
    {
        values->clear();
        if (!expect('['))
            return false;
        skip_ws();
        if (consume(']'))
            return true;
        while (true) {
            uint64_t value = 0;
            if (!parse_u64(&value))
                return false;
            values->push_back(value);
            skip_ws();
            if (consume(']'))
                return true;
            if (!consume(','))
                return fail("expected ',' or ']'");
        }
    }

    bool parse_index_array(std::vector<size_t>* values)
    {
        std::vector<uint64_t> raw;
        if (!parse_u64_array(&raw))
            return false;
        values->clear();
        values->reserve(raw.size());
        for (const uint64_t value : raw) {
            if (value > static_cast<uint64_t>(SIZE_MAX))
                return fail("index out of range");
            values->push_back(static_cast<size_t>(value));
        }
        return true;
    }

    bool parse_function(StaticGraphFunction* function)
    {
        if (!expect('{'))
            return false;
        skip_ws();
        if (consume('}'))
            return true;
        while (true) {
            std::string key;
            if (!parse_string(&key))
                return false;
            if (!expect(':'))
                return false;
            if (key == "name") {
                if (!parse_string(&function->name))
                    return false;
            } else if (key == "linkage_name") {
                if (!parse_string(&function->linkage_name))
                    return false;
            } else if (key == "low_pc") {
                if (!parse_u64(&function->low_pc))
                    return false;
            } else if (key == "high_pc") {
                if (!parse_u64(&function->high_pc))
                    return false;
            } else if (key == "file_offset") {
                if (!parse_u64(&function->file_offset))
                    return false;
            } else if (key == "has_code") {
                if (!parse_bool(&function->has_code))
                    return false;
            } else if (key == "exported") {
                if (!parse_bool(&function->exported))
                    return false;
            } else if (key == "address_taken") {
                if (!parse_bool(&function->address_taken))
                    return false;
            } else if (key == "entry") {
                if (!parse_bool(&function->entry))
                    return false;
            } else if (key == "init") {
                if (!parse_bool(&function->init))
                    return false;
            } else if (key == "return_offsets") {
                if (!parse_u64_array(&function->return_offsets))
                    return false;
            } else if (!skip_value()) {
                return false;
            }
            skip_ws();
            if (consume('}'))
                return true;
            if (!consume(','))
                return fail("expected ',' or '}'");
        }
    }

    bool parse_functions(std::vector<StaticGraphFunction>* functions)
    {
        functions->clear();
        if (!expect('['))
            return false;
        skip_ws();
        if (consume(']'))
            return true;
        while (true) {
            StaticGraphFunction function;
            if (!parse_function(&function))
                return false;
            functions->push_back(std::move(function));
            skip_ws();
            if (consume(']'))
                return true;
            if (!consume(','))
                return fail("expected ',' or ']'");
        }
    }

    bool parse_edges(std::vector<std::vector<size_t>>* edges)
    {
        edges->clear();
        if (!expect('['))
            return false;
        skip_ws();
        if (consume(']'))
            return true;
        while (true) {
            std::vector<size_t> callees;
            if (!parse_index_array(&callees))
                return false;
            edges->push_back(std::move(callees));
            skip_ws();
            if (consume(']'))
                return true;
            if (!consume(','))
                return fail("expected ',' or ']'");
        }
    }

    bool parse_module(StaticGraphModule* module)
    {
        if (!expect('{'))
            return false;
        skip_ws();
        if (consume('}'))
            return fail("module object is empty");
        while (true) {
            std::string key;
            if (!parse_string(&key))
                return false;
            if (!expect(':'))
                return false;
            if (key == "path") {
                if (!parse_string(&module->path))
                    return false;
            } else if (key == "build_id") {
                if (!parse_string(&module->build_id))
                    return false;
            } else if (key == "arch") {
                if (!parse_string(&module->arch))
                    return false;
            } else if (key == "is_64bit") {
                if (!parse_bool(&module->is_64bit))
                    return false;
            } else if (key == "prunable") {
                if (!parse_bool(&module->prunable))
                    return false;
            } else if (key == "prune_reason") {
                if (!parse_string(&module->prune_reason))
                    return false;
            } else if (key == "functions") {
                if (!parse_functions(&module->functions))
                    return false;
            } else if (key == "edges") {
                if (!parse_edges(&module->edges))
                    return false;
            } else if (key == "roots") {
                if (!parse_index_array(&module->roots))
                    return false;
            } else if (!skip_value()) {
                return false;
            }
            skip_ws();
            if (consume('}'))
                break;
            if (!consume(','))
                return fail("expected ',' or '}'");
        }

        if (module->edges.size() != module->functions.size()) {
            return fail("module '" + module->path + "' has " +
                        std::to_string(module->functions.size()) +
                        " function(s) but " +
                        std::to_string(module->edges.size()) +
                        " edge list(s)");
        }
        for (const auto& callees : module->edges) {
            for (const size_t target : callees) {
                if (target >= module->functions.size())
                    return fail("edge index out of range in module '" +
                                module->path + "'");
            }
        }
        // Out-of-range roots are advisory only; drop them.
        module->roots.erase(
            std::remove_if(module->roots.begin(), module->roots.end(),
                           [&](size_t root) {
                               return root >= module->functions.size();
                           }),
            module->roots.end());
        return true;
    }

    bool parse_modules(std::vector<StaticGraphModule>* modules)
    {
        modules->clear();
        if (!expect('['))
            return false;
        skip_ws();
        if (consume(']'))
            return true;
        while (true) {
            StaticGraphModule module;
            if (!parse_module(&module))
                return false;
            modules->push_back(std::move(module));
            skip_ws();
            if (consume(']'))
                return true;
            if (!consume(','))
                return fail("expected ',' or ']'");
        }
    }

    bool parse_document(StaticGraphDocument* document)
    {
        if (!expect('{'))
            return false;
        bool have_format = false;
        bool have_version = false;
        uint64_t version = 0;

        skip_ws();
        if (consume('}'))
            return fail("empty document");
        while (true) {
            std::string key;
            if (!parse_string(&key))
                return false;
            if (!expect(':'))
                return false;
            if (key == "format") {
                std::string format;
                if (!parse_string(&format))
                    return false;
                if (format != kStaticGraphFormat)
                    return fail("not a " + std::string(kStaticGraphFormat) +
                                " document");
                have_format = true;
            } else if (key == "version") {
                if (!parse_u64(&version))
                    return false;
                have_version = true;
            } else if (key == "modules") {
                if (!parse_modules(&document->modules))
                    return false;
            } else if (!skip_value()) {
                return false;
            }
            skip_ws();
            if (consume('}'))
                break;
            if (!consume(','))
                return fail("expected ',' or '}'");
        }

        if (!have_format)
            return fail("missing format field");
        if (!have_version)
            return fail("missing version field");
        if (version != static_cast<uint64_t>(kStaticGraphFormatVersion)) {
            return fail("unsupported version " + std::to_string(version) +
                        " (this build supports " +
                        std::to_string(kStaticGraphFormatVersion) + ")");
        }
        return true;
    }

    const std::string& text_;
    size_t pos_ = 0;
    std::string reason_;
};

bool same_path(const std::string& a, const std::string& b)
{
    if (a == b)
        return true;
    std::error_code error;
    const auto canonical_a = std::filesystem::weakly_canonical(a, error);
    if (error)
        return false;
    error.clear();
    const auto canonical_b = std::filesystem::weakly_canonical(b, error);
    if (error)
        return false;
    return canonical_a == canonical_b;
}

}  // namespace

bool read_static_graph_json(const std::string& text,
                            StaticGraphDocument* document, std::string* reason)
{
    Parser parser(text);
    document->modules.clear();
    if (!parser.parse(document)) {
        if (reason)
            *reason = parser.reason();
        document->modules.clear();
        return false;
    }
    return true;
}

const StaticGraphModule* find_static_graph_module(
    const StaticGraphDocument& document, const std::string& build_id,
    const std::string& path)
{
    if (!build_id.empty()) {
        for (const auto& module : document.modules) {
            if (module.build_id == build_id)
                return &module;
        }
    }
    if (!path.empty()) {
        for (const auto& module : document.modules) {
            if (same_path(module.path, path))
                return &module;
        }
    }
    return nullptr;
}

bool join_static_graph_module(const StaticGraphModule& module,
                              const std::vector<FunctionInfo>& functions,
                              StaticGraphFacts* facts)
{
    facts->edges.assign(functions.size(), {});
    facts->entry.clear();
    facts->init.clear();
    facts->exports.clear();
    facts->address_taken.clear();
    facts->return_offsets.assign(functions.size(), {});
    facts->has_returns = false;
    facts->prunable = module.prunable;
    facts->prune_reason = module.prune_reason;

    std::unordered_map<uint64_t, size_t> by_pc;
    by_pc.reserve(functions.size() * 2);
    for (size_t i = 0; i < functions.size(); ++i) {
        // First definition wins for aliases at the same address.
        by_pc.emplace(functions[i].low_pc, i);
    }

    size_t matched = 0;
    for (size_t gi = 0; gi < module.functions.size(); ++gi) {
        const StaticGraphFunction& source = module.functions[gi];
        const auto it = by_pc.find(source.low_pc);
        if (it == by_pc.end())
            continue;
        ++matched;
        const size_t index = it->second;

        if (gi < module.edges.size()) {
            std::vector<size_t>& callees = facts->edges[index];
            for (const size_t target : module.edges[gi]) {
                if (target >= module.functions.size())
                    continue;
                const auto target_it =
                    by_pc.find(module.functions[target].low_pc);
                if (target_it == by_pc.end())
                    continue;
                if (std::find(callees.begin(), callees.end(),
                              target_it->second) == callees.end())
                    callees.push_back(target_it->second);
            }
        }

        if (source.entry)
            facts->entry.push_back(index);
        if (source.init)
            facts->init.push_back(index);
        if (source.exported)
            facts->exports.push_back(index);
        if (source.address_taken)
            facts->address_taken.push_back(index);
        if (!source.return_offsets.empty()) {
            facts->return_offsets[index] = source.return_offsets;
            facts->has_returns = true;
        }
    }

    if (matched == 0) {
        facts->edges.clear();
        facts->return_offsets.clear();
        return false;
    }
    return true;
}

size_t apply_static_graph_returns(const StaticGraphFacts& facts,
                                  std::vector<FunctionInfo>* functions)
{
    size_t applied = 0;
    const size_t count =
        std::min(facts.return_offsets.size(), functions->size());
    for (size_t i = 0; i < count; ++i) {
        if (facts.return_offsets[i].empty())
            continue;
        (*functions)[i].return_offsets = facts.return_offsets[i];
        ++applied;
    }
    return applied;
}

std::vector<size_t> static_graph_module_roots(const StaticGraphModule& module)
{
    std::vector<FunctionInfo> functions(module.functions.size());
    std::vector<size_t> entry;
    std::vector<size_t> init;
    std::vector<size_t> exports;
    std::vector<size_t> address_taken;

    for (size_t i = 0; i < module.functions.size(); ++i) {
        const StaticGraphFunction& source = module.functions[i];
        functions[i].name = source.name;
        functions[i].linkage_name = source.linkage_name;
        functions[i].low_pc = source.low_pc;
        if (source.entry)
            entry.push_back(i);
        if (source.init)
            init.push_back(i);
        if (source.exported)
            exports.push_back(i);
        if (source.address_taken)
            address_taken.push_back(i);
    }

    return static_graph_roots(functions, entry, init, exports, address_taken);
}

}  // namespace callgraph
