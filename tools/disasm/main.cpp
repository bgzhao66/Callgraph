// SPDX-License-Identifier: GPL-3.0-only
// callgraph-disasm: static call-graph facts for one ELF module.
//
// This program is the only part of the project that links libopcodes, so it
// is distributed under GPL-3.0-only.  It emits JSON facts; callgraph consumes
// them with --static-graph.

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

#include "callgraph/elf_resolver.h"
#include "callgraph/module_dependencies.h"
#include "callgraph/static_graph_build.h"
#include "callgraph/static_graph_json.h"

namespace {

const char* kProgram = "callgraph-disasm";

void usage(FILE* out)
{
    fprintf(out,
            "usage: callgraph disasm [<options>] <module>\n"
            "\n"
            "Emit static call-graph facts for an ELF executable or shared\n"
            "object.  <module> must retain its symbol table and be x86-64.\n"
            "\n"
            "Options:\n"
            "  -o, --output <file>  write JSON facts to <file> (default: stdout)\n"
            "      --all-modules    <module> plus its transitive DT_NEEDED closure\n"
            "  -h, --help           show this help\n"
            "      --version        print version and libopcodes availability\n"
            "\n"
            "The output is consumed by:\n"
            "  callgraph run --static-graph <file> ...\n"
            "  callgraph export --static --static-graph <file>\n",
            kProgram);
}

int usage_error(const std::string& message)
{
    fprintf(stderr, "%s: %s\n", kProgram, message.c_str());
    fprintf(stderr, "%s: use --help for usage\n", kProgram);
    return 2;
}

std::string canonical_path(const std::string& path)
{
    std::error_code error;
    const auto canonical = std::filesystem::weakly_canonical(path, error);
    if (error)
        return path;
    return canonical.string();
}

struct Options {
    std::string output;
    std::string module;
    bool all_modules = false;
    bool help = false;
    bool version = false;
};

bool parse_args(int argc, char** argv, Options* options, std::string* error)
{
    std::vector<std::string> positionals;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto value = [&](const char* name) -> std::string {
            if (i + 1 >= argc) {
                *error = std::string("option ") + name + " requires a value";
                return {};
            }
            return argv[++i];
        };

        if (arg == "-h" || arg == "--help") {
            options->help = true;
        } else if (arg == "--version") {
            options->version = true;
        } else if (arg == "--all-modules") {
            options->all_modules = true;
        } else if (arg == "-o" || arg == "--output") {
            options->output = value(arg.c_str());
            if (!error->empty())
                return false;
        } else if (arg.rfind("-", 0) == 0 && arg != "-") {
            *error = "unknown option '" + arg + "'";
            return false;
        } else {
            positionals.push_back(arg);
        }
    }

    if (options->help || options->version)
        return true;
    if (positionals.size() != 1) {
        *error = "expected exactly one MODULE argument";
        return false;
    }
    options->module = positionals.front();
    return true;
}

bool build_module(const std::string& path, bool required,
                  callgraph::StaticGraphModule* module)
{
    using namespace callgraph;

    const ResolveOptions resolve_options{false};
    ModuleInfo info;
    try {
        info = ElfResolver::resolve(path, resolve_options);
    } catch (const std::exception& error) {
        if (required) {
            fprintf(stderr, "%s: cannot analyze %s: %s\n", kProgram,
                    path.c_str(), error.what());
        } else {
            fprintf(stderr, "%s: skipping dependency %s: %s\n", kProgram,
                    path.c_str(), error.what());
        }
        return false;
    }

    StaticGraphBuildRequest request;
    request.path = canonical_path(path);
    request.build_id = info.build_id;
    request.functions = &info.functions;

    std::string reason;
    if (!build_static_graph_module(request, module, &reason)) {
        if (required) {
            fprintf(stderr, "%s: cannot build a static call graph for %s: %s\n",
                    kProgram, path.c_str(), reason.c_str());
        } else {
            fprintf(stderr, "%s: skipping dependency %s: %s\n", kProgram,
                    path.c_str(), reason.c_str());
        }
        return false;
    }
    if (!module->prunable) {
        fprintf(stderr,
                "%s: warning: %s: %s; only return offsets are usable\n",
                kProgram, path.c_str(), module->prune_reason.c_str());
    }
    return true;
}

}  // namespace

int main(int argc, char** argv)
{
    Options options;
    std::string error;
    if (!parse_args(argc, argv, &options, &error))
        return usage_error(error);

    if (options.help) {
        usage(stdout);
        return 0;
    }
    if (options.version) {
#ifdef CALLGRAPH_VERSION
        printf("%s %s\n", kProgram, CALLGRAPH_VERSION);
#else
        printf("%s unknown\n", kProgram);
#endif
        printf("libopcodes: yes\n");
        return 0;
    }

    std::vector<std::string> paths;
    if (options.all_modules) {
        std::string reason;
        if (!callgraph::module_dependencies(options.module, &paths, &reason)) {
            fprintf(stderr, "%s: cannot resolve dependencies of %s: %s\n",
                    kProgram, options.module.c_str(), reason.c_str());
            return 1;
        }
    } else {
        paths.push_back(options.module);
    }

    callgraph::StaticGraphDocument document;
    for (size_t i = 0; i < paths.size(); ++i) {
        callgraph::StaticGraphModule module;
        if (!build_module(paths[i], i == 0, &module)) {
            if (i == 0)
                return 1;
            continue;
        }
        document.modules.push_back(std::move(module));
    }

    if (document.modules.empty()) {
        fprintf(stderr, "%s: no modules were analyzed\n", kProgram);
        return 1;
    }

    const std::string json = callgraph::write_static_graph_json(document);
    if (!options.output.empty() && options.output != "-") {
        std::ofstream file(options.output, std::ios::binary);
        if (!file) {
            fprintf(stderr, "%s: cannot open %s for writing\n", kProgram,
                    options.output.c_str());
            return 1;
        }
        file.write(json.data(), static_cast<std::streamsize>(json.size()));
        file.flush();
        if (!file) {
            fprintf(stderr, "%s: cannot write %s\n", kProgram,
                    options.output.c_str());
            return 1;
        }
    } else {
        if (fwrite(json.data(), 1, json.size(), stdout) != json.size()) {
            fprintf(stderr, "%s: cannot write facts to stdout\n", kProgram);
            return 1;
        }
    }

    return 0;
}
