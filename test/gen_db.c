#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define CWMP_MAX_CPE_DIGIT_NUMBER       7           /* Maximum milion devices */
#define CWMP_SERIAL_STR                 "%s%0*d"

#define SAFE_FILE_CLOSE(__X__)          do {                                    \
                                            if (__X__ != NULL) fclose(__X__);   \
                                            __X__ = NULL;                       \
                                        } while (0);

#define SAFE_FREE(__X__)          		do {                                    \
                                            if (__X__ != NULL) free  (__X__);   \
                                            __X__ = NULL;                       \
                                        } while (0);

void
print_help (void)
{
    printf ("Generate CPE database for mongodb. By quyenlv @2017.\n");
    printf ("Usage: gen_db TEMP_FILE SERIAL QUANTITY\n");
    printf ("\nParameters:\n");
    printf ("  TEMP_FILE                 Input file contains template for generated element\n");
    printf ("  SERIAL                    Prefix serial number of generated CPE\n");
    printf ("  QUANTITY                  Quantity of generated CPEs\n");
    printf ("\nTips:\n");
    printf ("  TEMP_FILE should contain only one sample CPE element. You can connect a desired\n"
            "  device to ACS and export mongo database of it through this command:\n\n"
            "      mongoexport --db genieacs --collection devices --out template.json\n\n"
            "  Then open the template.json file and change the serial number value to %%s.\n"
            "  We will replace this field with the input SERIAL prefix, followed by index number.\n"
            "  After using this tool to generate the new database, import it to mongo:\n\n"
            "      mongoimport --db genieacs --collection devices --file db.json\n");
}

int main (int argc, char *argv[])
{
    const char* output = "db.json";
    FILE *fp = NULL;
    FILE *fo = NULL;
    char *line = NULL;
    char *serial = NULL;
    char *serial_prefix = NULL;
    size_t len = 0;
    ssize_t read;
    int ret, total, serial_len, i;

    if (argc != 4)
    {
        print_help();
        return -1;
    }

    serial_prefix = argv[2];

    total = atoi(argv[3]);
    if (total <= 0)
    {
        fprintf (stderr, "Number of elements invalid: \"%s\"\n", argv[3]);
        return -1;
    }


    fp = fopen (argv[1], "r");
    if (NULL == fp)
    {
        fprintf (stderr, "Cannot open file %s.\n", argv[1]);
        return -1;
    }

    fo = fopen (output, "w");
    if (NULL == fo)
    {
        fprintf (stderr, "Cannot open file %s\n", output);
        goto __out;
    }

    read = getline (&line, &len, fp);
    if (-1 == read)
    {
        fprintf (stderr, "Cannot load the database template.\n");
        goto __out;
    }

    serial_len = strlen (serial_prefix) + CWMP_MAX_CPE_DIGIT_NUMBER + 1;
    serial = malloc (serial_len);
    if (NULL == serial)
    {
        fprintf (stderr, "Not enough memory\n");
        goto __out;
    }

    for (i = 1; i <= total; i++)
    {
        ret = snprintf (serial, serial_len, CWMP_SERIAL_STR, serial_prefix,
                        CWMP_MAX_CPE_DIGIT_NUMBER, i);
        if (ret >= serial_len)
        {
            fprintf (stderr, "snprintf was truncated.\n");
            goto __out;
        }

        fprintf (fo, line, serial, serial, serial); 
    }

__out:
    SAFE_FILE_CLOSE (fp);
    SAFE_FILE_CLOSE (fo);
	SAFE_FREE (serial);

    return 0;
}
