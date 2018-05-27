
/* =====[ cmdline.h ]=========================================================

   Description:     Encryption excamples. Feasability study for diba
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  aug.23.2017     Peter Glen      Extracted from gcry

   ======================================================================= */

typedef struct _opts
{
    char    opt;
    char    *long_opt;
    int     *val;
    char    **strval;
    int     minval, maxval;
    int     *flag;
    char    *help;
} opts;

int     parse_commad_line(char **argv, opts *popts_data, char **err_str);
void    usage(const char *progname, const char *desc, opts *opts_data);



