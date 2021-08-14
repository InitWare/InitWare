#  -*- Mode: python; coding: utf-8; indent-tabs-mode: nil -*- */
#
#  This file is part of systemd.
#
#  Copyright 2012 Lennart Poettering
#  Copyright 2013 Zbigniew Jędrzejewski-Szmek
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
#
#  systemd is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with systemd; If not, see <http://www.gnu.org/licenses/>.

import collections
import sys
import re
from xml_helper import *

MDASH = ' — ' if sys.version_info.major >= 3 else ' -- '

TEMPLATE = '''\
<refentry version="5.1" xmlns="http://docbook.org/ns/docbook"
          xmlns:xlink="http://www.w3.org/1999/xlink"
          xmlns:xila="http://www.w3.org/2001/XInclude/local-attributes"
          xmlns:xi="http://www.w3.org/2001/XInclude"
          xmlns:trans="http://docbook.org/ns/transclusion"
          xmlns:svg="http://www.w3.org/2000/svg"
          xmlns:m="http://www.w3.org/1998/Math/MathML"
          xmlns:html="http://www.w3.org/1999/xhtml"
          xmlns:db="http://docbook.org/ns/docbook">

  <refentryinfo>
    <title>Contents</title>
    <productname>InitWare Suite of Middleware</productname>
  </refentryinfo>

  <refmeta>
    <refentrytitle>Contents</refentrytitle>
    <manvolnum>7</manvolnum>
    <refmiscinfo class="source">InitWare 0.7alpha</refmiscinfo>
  </refmeta>

  <refsect1 id='contents'>
    <title>InitWare Suite of Middleware Manual Pages</title>
    <para>
    <variablelist>

    </variablelist>
    </para>
  </refsect1>

</refentry>
'''

SUMMARY = '''\
  <refsect1>
    <para id='counts' />
  </refsect1>
'''

COUNTS = '\
This index contains {count} entries, referring to {pages} individual manual pages.'

ns = {'db': 'http://docbook.org/ns/docbook', } # add more as needed

def make_index(pages):
    index = collections.defaultdict(list)
    for p in pages:
        t = xml_parse(p)
        section = t.find('./db:refmeta/db:manvolnum', ns).text
        refname = t.find('./db:refnamediv/db:refname', ns).text
        purpose = ' '.join(t.find('./db:refnamediv/db:refpurpose', ns).text.split())
        for f in t.findall('./db:refnamediv/db:refname', ns):
            infos = (f.text, section, purpose, refname)
            index[section].append(infos)
    return index

def add_letter(template, letter, pages):
    clist = template.find("./db:refsect1[@id='contents']/db:para/db:variablelist", ns)
    varlistentry = tree.SubElement(clist, 'varlistentry')
    term = tree.SubElement(varlistentry, 'term')
    listitem = tree.SubElement(varlistentry, 'listitem')
    term.text = "Section " + letter
    para = tree.SubElement(listitem, 'para')
    for info in sorted(pages, key=lambda info: str.lower(info[0])):
        refname, section, purpose, realname = info

        b = tree.SubElement(para, 'citerefentry')
        c = tree.SubElement(b, 'refentrytitle')
        c.text = refname
        d = tree.SubElement(b, 'manvolnum')
        d.text = section

        b.tail = MDASH + purpose # + ' (' + p + ')'

        tree.SubElement(para, 'sbr')

def add_summary(template, indexpages):
    count = 0
    pages = set()
    for group in indexpages:
        count += len(group)
        for info in group:
            refname, section, purpose, realname = info
            pages.add((realname, section))

    refsect1 = tree.fromstring(SUMMARY)
    template.append(refsect1)

    para = template.find(".//para[@id='counts']")
    para.text = COUNTS.format(count=count, pages=len(pages))

def make_page(*xml_files):
    try:
      tree.register_namespace('', "http://docbook.org/ns/docbook")
    except:
      pass

    template = tree.fromstring(TEMPLATE)
    index = make_index(xml_files)

    for letter in sorted(index):
        add_letter(template, letter, index[letter])

    add_summary(template, index.values())

    return template

if __name__ == '__main__':
    with open(sys.argv[1], 'wb') as f:
        f.write(xml_print(make_page(*sys.argv[2:])))
