#pragma once

#include <optional>
#include <string>

extern std::string arg_path, arg_out, arg_rand_str, arg_encrypt_section_name;
extern int arg_rand;
extern bool arg_sub, arg_shuffle;

std::optional<bool> parse_args( int argc, char* argv[] );