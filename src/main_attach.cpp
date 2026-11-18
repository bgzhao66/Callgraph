#include "cli_internal.h"

int main(int argc, char** argv)
{
    return callgraph::trace_program(argc, argv, callgraph::ProgramMode::Attach);
}
