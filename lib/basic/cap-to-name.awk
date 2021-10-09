# SPDX-License-Identifier: LGPL-2.1-or-later

BEGIN{
        print "static const char* const cap_names[] = { "
}
{
        printf "        [%s] = \"%s\",\n", $1, tolower($1)
}
END{
        print "};"
}
