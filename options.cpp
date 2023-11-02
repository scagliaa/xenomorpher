#include "options.h"
#include <iostream>
#include <optional>
#include <charconv>
#include <string_view>

#include "getopt.h"

std::string arg_path, arg_out, arg_rand_str, arg_encrypt_section_name;
int arg_rand{ 65 };
bool arg_substitute{ false }, arg_shuffle{ false };

std::optional<bool> parse_args( int argc, char* argv[] ) {
    int c;
    while ((c = getopt(argc, argv, "sSho:r:e:")) != -1) {
        switch (c) {
        case 'h':
            std::cout << "XENOMORPHER - Generic Metamorphic Engine\n"
                "This program is designed to perform various operations on input files based on the provided command-line arguments.\n\n"
                "Usage: xm [-hs] [-e s] [-r n] -o output input\n\n"
                "Options:\n"
                "-o f\tOutput file: Specifies the path to the output file. This is where the results of the operations will be written.\n"
                "-r n\tProbability: This option takes a numerical argument between 1 and 100. It represents the probability of each operation of the transforms being performed. The default value is 65.\n"
                "-h \tHelp: Shows this help information.\n"
                "-s \tSubstitution: When this option is used, the program performs in-place substitution. It replaces instructions with equivalent instructions of the same size.\n"
                "-S \tShuffle: This option enables the shuffling of small blocks of instructions when their order isn't important.\n"
                "-e s\tEncryption: This option takes the name of a section as an argument. The specified section will be encrypted, and the entry point will be moved to a polymorphic decryptor.\n\n"
                "Please note that the order of the options matters. Also, make sure to provide the necessary arguments for each option.\n"
                "For any further assistance, please refer to the documentation or contact the support team.\n";
            return std::nullopt;
        case 's':
            arg_substitute = true;
            break;
        case 'S':
            arg_shuffle = true;
            break;
        case 'o':
            arg_out = optarg;
            break;
        case 'r':
            arg_rand_str = optarg;
            break;
        case 'e':
            arg_encrypt_section_name = optarg;
            break;
        case '?':
            if (optopt == 'o')
                std::cerr << "Option -o requires an argument.\n";
            else if (optopt == 'r')
                std::cerr << "Option -r requires a numerical argument.\n";
            else if (optopt == 'e')
                std::cerr << "Option -e requires the name of a section.\n";
            else if (isprint(optopt))
                std::cerr << "Unknown option or missing argument\n";
            else
                std::cerr << "Unknown option character\n";
            return false;
        default:
            return false;
        }
    }
    if (optind < argc) {
        arg_path = argv[optind];
    }
    else {
        std::cerr << "Error: no input file.\n";
        return false;
    }
    if (!arg_rand_str.empty()) {
        int result;
        if ( auto [p, ec] = std::from_chars(arg_rand_str.data(), arg_rand_str.data() + arg_rand_str.size(), result); ec == std::errc() && result >= 1 && result <= 100)
            arg_rand = result;
        else {
            std::cerr << "Error: Option -r requires a numerical argument between 1 and 100\n";
            return false;
        }
    }
    return true;
}