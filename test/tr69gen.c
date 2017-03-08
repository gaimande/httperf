#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_LEN		1024

/* return a new string with every instance of ch replaced by repl */
char *replaceStr(const char *s, char ch, const char *repl) {
    int count = 0;
    const char *t;
    for(t=s; *t; t++)
        count += (*t == ch);

    size_t rlen = strlen(repl);
    char *res = malloc(strlen(s) + (rlen-1)*count + 1);
    char *ptr = res;
    for(t=s; *t; t++) {
        if(*t == ch) {
            memcpy(ptr, repl, rlen);
            ptr += rlen;
        } else {
            *ptr++ = *t;
        }
    }
    *ptr = 0;
    return res;
}

int main(int argc, char *argv[])
{
	const char* soap_begin = "<SOAP-ENV:Envelope";
	const char* soap_end = "</SOAP-ENV:Envelope>";
	const char* script_heading = "    / method=POST contents=\"";
	const char* script_trailing = "\"";
	FILE *fp = NULL;
	FILE *fw = NULL;
	char line[MAX_LEN] = {0};
	char *buf = NULL;
	char *end = NULL;
	char *r_buf = NULL;
	int parse_new_soap = 0;

	fp = fopen (argv[1], "r");
	if (NULL == fp)
	{
		fprintf (stderr, "Cannot open file %s\n", argv[1]);
		return -1;
	}

	fw = fopen ("output", "w");
	if (NULL == fw)
	{
		fprintf (stderr, "Cannot open file %s\n", fw);
		return -1;
	}

	while (fgets (line, sizeof(line), fp) != NULL)
	{
		if (0 == parse_new_soap && NULL == strstr(line, soap_begin))
		{
			continue;
		}

		buf = line;

		if (0 == parse_new_soap)
		{
			fputs (script_heading, fw);
			parse_new_soap = 1;
		}

		if (NULL != strstr (buf, "<cwmp:ID"))
		{
			fputs ("<cwmp:ID SOAP-ENV:mustUnderstand=\\\"1\\\">\%s</cwmp:ID>", fw);
			continue;
		}
		else if (NULL != strstr (buf, "<SerialNumber>"))
		{
			fputs ("<SerialNumber>\%s</SerialNumber>", fw);
			continue;
		}
		else if (NULL != strstr (buf, "<Value xsi:type=\"xsd:string\">DSNW"))
		{
			fputs ("<Value xsi:type=\\\"xsd:string\\\">\%s</Value>", fw);
			continue;
		}

		/* Remove leading white space */
		while(isspace((unsigned char)*buf)) buf++;
		if ('\0' == *buf)
		{
			continue;
		}

		r_buf = replaceStr (buf, '"', "\\\"");
		/* Remove trailing newline */
		end = r_buf + strlen(r_buf) -1;
		while (end > r_buf &&
			   (*end == '\n'|| *end == '\r'))
		{
			end--;
		}
		*(end+1) = '\0';
		fputs (r_buf, fw);

		/* Check long object */
		if (NULL == strstr(r_buf, ">"))
		{
			fputs (" ", fw);
		}

		if (strstr(r_buf, soap_end) != NULL)
		{
			fputs (script_trailing, fw);
			fputs ("\n", fw);
			parse_new_soap = 0;
		}

		free (r_buf);
		r_buf = NULL;
	}

	fclose (fp);
	fclose (fw);

	return 0;
}
