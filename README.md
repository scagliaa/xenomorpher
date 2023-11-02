# Generic Metamorphic Engine / In development
# This program is designed to perform various operations on input files based on the provided command-line arguments.

-o | Output file: Specifies the path to the output file. This is where the results of the operations will be written.

-r | Probability: This option takes a numerical argument between 1 and 100. It represents the probability of each operation of the transforms being performed. The default value is 65

-s | Substitution: When this option is used, the program performs in-place substitution. It replaces instructions with equivalent instructions of the same size

-S | Shuffle: This option enables the shuffling of small blocks of instructions when their order isn't important.\n"

-e s | Encryption: This option takes the name of a section as an argument. The specified section will be encrypted, and the entry point will be moved to a polymorphic decryptor.
