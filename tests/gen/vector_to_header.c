// Transforms a test vector file (from stdin) into a C header.

#include <stdio.h>
#include <inttypes.h>
#include <stddef.h>

static int is_digit(int c)
{
    return (c >= '0' && c <= '9')
        || (c >= 'a' && c <= 'f')
        || (c >= 'A' && c <= 'F');
}

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "Wrong use of vector transformer. Give one argument\n");
        return 1;
    }

    char *prefix = argv[1];
    int   c      = getchar();
    int   nb_vec = 0;

    while (c != EOF) {
        int size = 0;
        if (c == ':') {
            // Empty lines can't be C arrays.
            // We make them null pointers instead
            printf("#define %s_%d 0\n", prefix, nb_vec);
        }
        else {
            printf("uint8_t %s_%d[] = { ", prefix, nb_vec);
            while (c != ':') {
                char msb = (char)c;  c = getchar();
                char lsb = (char)c;  c = getchar();
                printf("0x%c%c, ", msb, lsb);
                size ++;
            }
            printf("};\n");
        }
        c = getchar();
        printf("#define %s_%d_size %d\n", prefix, nb_vec, size);

        // seek next line
        while (!is_digit(c) && c != ':' && c != EOF) {
            c = getchar();
        }
        nb_vec++;
    }

    printf("size_t nb_%s_vectors = %d;\n", prefix, nb_vec);

    printf("uint8_t *%s_vectors[] = { ", prefix);
    for (int i = 0; i < nb_vec; i++) {
        printf("%s_%d, ", prefix, i);
    }
    printf("};\n");

    printf("size_t %s_sizes[] = { ", prefix);
    for (int i = 0; i < nb_vec; i++) {
        printf("%s_%d_size, ", prefix, i);
    }
    printf("};\n");
}
