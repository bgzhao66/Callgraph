#include "callgraph/dwarf_args.h"

#include <dwarf.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>

#include <cstdlib>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "callgraph/argument_info.h"

namespace callgraph {
namespace {

uint32_t type_size(Dwarf_Die* die)
{
    const int size = dwarf_bytesize(die);
    if (size < 0 ||
        static_cast<unsigned long>(size) >
            std::numeric_limits<uint32_t>::max())
        return 0;
    return static_cast<uint32_t>(size);
}

bool follow_type(Dwarf_Die* die, Dwarf_Die* out)
{
    Dwarf_Attribute attr;
    if (!dwarf_attr_integrate(die, DW_AT_type, &attr))
        return false;
    return dwarf_formref_die(&attr, out) != nullptr;
}

bool is_qualifier(int tag)
{
    switch (tag) {
    case DW_TAG_typedef:
    case DW_TAG_const_type:
    case DW_TAG_volatile_type:
    case DW_TAG_restrict_type:
#ifdef DW_TAG_atomic_type
    case DW_TAG_atomic_type:
#endif
        return true;
    default:
        return false;
    }
}

bool type_contains_float(Dwarf_Die* die, int depth)
{
    if (depth > 8)
        return false;

    const int tag = dwarf_tag(die);
    if (is_qualifier(tag)) {
        Dwarf_Die next;
        return follow_type(die, &next) &&
               type_contains_float(&next, depth + 1);
    }

    if (tag == DW_TAG_base_type) {
        Dwarf_Attribute attr;
        Dwarf_Word encoding = 0;
        return dwarf_attr_integrate(die, DW_AT_encoding, &attr) &&
               dwarf_formudata(&attr, &encoding) == 0 &&
               encoding == DW_ATE_float;
    }

    if (tag == DW_TAG_array_type) {
        Dwarf_Die element;
        return follow_type(die, &element) &&
               type_contains_float(&element, depth + 1);
    }

    if (tag != DW_TAG_structure_type && tag != DW_TAG_union_type &&
        tag != DW_TAG_class_type)
        return false;

    Dwarf_Die child;
    if (dwarf_child(die, &child) != 0)
        return false;

    do {
        if (dwarf_tag(&child) != DW_TAG_member)
            continue;

        Dwarf_Attribute attr;
        Dwarf_Die member_type;
        if (dwarf_attr_integrate(&child, DW_AT_type, &attr) &&
            dwarf_formref_die(&attr, &member_type) &&
            type_contains_float(&member_type, depth + 1))
            return true;
    } while (dwarf_siblingof(&child, &child) == 0);

    return false;
}

void describe_type(Dwarf_Die* die, ParameterInfo& parameter, int depth)
{
    if (depth > 8) {
        parameter.kind = ArgumentKind::Unknown;
        return;
    }

    const int tag = dwarf_tag(die);
    if (is_qualifier(tag)) {
        Dwarf_Die next;
        if (follow_type(die, &next))
            describe_type(&next, parameter, depth + 1);
        else
            parameter.kind = ArgumentKind::Unknown;
        return;
    }

    switch (tag) {
    case DW_TAG_pointer_type:
    case DW_TAG_reference_type:
    case DW_TAG_rvalue_reference_type:
        parameter.kind = ArgumentKind::Pointer;
        parameter.byte_size = type_size(die);
        if (parameter.byte_size == 0)
            parameter.byte_size = 8;
        parameter.type_name = "pointer";
        return;

    case DW_TAG_base_type: {
        const char* name = dwarf_diename(die);
        parameter.type_name = name ? name : "?";
        parameter.byte_size = type_size(die);

        Dwarf_Attribute attr;
        Dwarf_Word encoding = 0;
        if (dwarf_attr_integrate(die, DW_AT_encoding, &attr) &&
            dwarf_formudata(&attr, &encoding) == 0) {
            switch (encoding) {
            case DW_ATE_boolean:
                parameter.kind = ArgumentKind::Boolean;
                break;
            case DW_ATE_float:
                parameter.kind = ArgumentKind::Float;
                break;
            case DW_ATE_signed:
                parameter.kind = ArgumentKind::Integer;
                parameter.is_signed = true;
                break;
            case DW_ATE_signed_char:
                parameter.kind = ArgumentKind::Char;
                parameter.is_signed = true;
                break;
            case DW_ATE_unsigned:
                parameter.kind = ArgumentKind::Unsigned;
                break;
            case DW_ATE_unsigned_char:
                parameter.kind = ArgumentKind::Char;
                break;
            case DW_ATE_UTF:
                parameter.kind = ArgumentKind::Unsigned;
                break;
            default:
                parameter.kind = ArgumentKind::Unknown;
                break;
            }
        }
        return;
    }

    case DW_TAG_enumeration_type: {
        parameter.kind = ArgumentKind::Integer;
        parameter.is_signed = true;
        parameter.byte_size = type_size(die);
        if (parameter.byte_size == 0)
            parameter.byte_size = 4;

        const char* name = dwarf_diename(die);
        parameter.type_name = name ? std::string("enum ") + name : "enum";

        // DWARF 4 and later may name the underlying type.
        Dwarf_Die underlying;
        if (follow_type(die, &underlying)) {
            ParameterInfo base;
            describe_type(&underlying, base, depth + 1);
            if (base.byte_size != 0)
                parameter.byte_size = base.byte_size;
            parameter.is_signed = base.is_signed;
        }
        return;
    }

    case DW_TAG_structure_type:
    case DW_TAG_union_type:
    case DW_TAG_class_type: {
        parameter.kind = ArgumentKind::Aggregate;
        parameter.byte_size = type_size(die);
        parameter.contains_float = type_contains_float(die, depth + 1);

        const char* name = dwarf_diename(die);
        const char* prefix = tag == DW_TAG_union_type   ? "union "
                             : tag == DW_TAG_class_type ? "class "
                                                        : "struct ";
        parameter.type_name = name ? std::string(prefix) + name : prefix;
        return;
    }

    case DW_TAG_array_type:
        parameter.kind = ArgumentKind::Aggregate;
        parameter.byte_size = type_size(die);
        parameter.contains_float = type_contains_float(die, depth + 1);
        parameter.type_name = "array";
        return;

    case DW_TAG_subroutine_type:
        parameter.kind = ArgumentKind::Pointer;
        parameter.byte_size = type_size(die);
        if (parameter.byte_size == 0)
            parameter.byte_size = 8;
        parameter.type_name = "function pointer";
        return;

    default:
        parameter.kind = ArgumentKind::Unknown;
        parameter.byte_size = type_size(die);
        return;
    }
}

void collect_parameters(Dwarf_Die* subprogram,
                        std::vector<ParameterInfo>& parameters)
{
    Dwarf_Die child;
    if (dwarf_child(subprogram, &child) != 0)
        return;

    do {
        if (dwarf_tag(&child) != DW_TAG_formal_parameter)
            continue;

        ParameterInfo parameter;
        const char* name = dwarf_diename(&child);
        if (name)
            parameter.name = name;

        Dwarf_Attribute attr;
        bool artificial = false;
        if (dwarf_attr_integrate(&child, DW_AT_artificial, &attr))
            dwarf_formflag(&attr, &artificial);
        parameter.artificial = artificial;

        Dwarf_Die type;
        if (dwarf_attr_integrate(&child, DW_AT_type, &attr) &&
            dwarf_formref_die(&attr, &type))
            describe_type(&type, parameter, 0);

        parameters.push_back(std::move(parameter));
    } while (dwarf_siblingof(&child, &child) == 0);
}

bool follow_origin(Dwarf_Die* die, Dwarf_Die* out)
{
    Dwarf_Attribute attr;
    if (dwarf_attr_integrate(die, DW_AT_abstract_origin, &attr) &&
        dwarf_formref_die(&attr, out))
        return true;
    if (dwarf_attr_integrate(die, DW_AT_specification, &attr) &&
        dwarf_formref_die(&attr, out))
        return true;
    return false;
}

void extract_signature(Dwarf_Die* subprogram, FunctionSignature& signature)
{
    signature.has_signature = true;
    collect_parameters(subprogram, signature.parameters);

    // A C++ definition DIE can carry only DW_AT_specification; parameters
    // then live on the declaration DIE.
    if (signature.parameters.empty()) {
        Dwarf_Die origin;
        if (follow_origin(subprogram, &origin))
            collect_parameters(&origin, signature.parameters);
    }

    classify_parameters(signature);
}

struct DwflGuard {
    Dwfl* dwfl;
    ~DwflGuard() { dwfl_end(dwfl); }
};

}  // namespace

std::size_t annotate_parameters(const std::string& path,
                                std::vector<FunctionInfo>& functions)
{
    if (functions.empty())
        return 0;

    Dwfl_Callbacks callbacks = {};
    callbacks.find_elf = dwfl_build_id_find_elf;
    callbacks.find_debuginfo = dwfl_standard_find_debuginfo;
    callbacks.section_address = dwfl_offline_section_address;
    callbacks.debuginfo_path = nullptr;

    Dwfl* dwfl = dwfl_begin(&callbacks);
    if (!dwfl)
        return 0;
    DwflGuard guard{dwfl};

    Dwfl_Module* module =
        dwfl_report_offline(dwfl, path.c_str(), path.c_str(), -1);
    if (!module)
        return 0;
    if (dwfl_report_end(dwfl, nullptr, nullptr) != 0)
        return 0;

    Dwarf_Addr bias = 0;
    Dwarf* dwarf = dwfl_module_getdwarf(module, &bias);
    if (!dwarf)
        return 0;

    std::size_t annotated = 0;
    for (auto& function : functions) {
        Dwarf_Die cudie;
        Dwarf_Die* cu = dwarf_addrdie(dwarf, function.low_pc, &cudie);
        if (!cu)
            continue;

        Dwarf_Die* scopes = nullptr;
        const int count = dwarf_getscopes(cu, function.low_pc, &scopes);
        if (count <= 0)
            continue;

        Dwarf_Die* subprogram = nullptr;
        for (int i = 0; i < count; ++i) {
            const int tag = dwarf_tag(&scopes[i]);
            if (tag == DW_TAG_subprogram || tag == DW_TAG_inlined_subroutine) {
                subprogram = &scopes[i];
                break;
            }
        }

        if (subprogram) {
            FunctionSignature signature;
            extract_signature(subprogram, signature);
            function.signature = std::move(signature);
            ++annotated;
        }

        free(scopes);
    }

    return annotated;
}

}  // namespace callgraph
