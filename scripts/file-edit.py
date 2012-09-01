#!/usr/bin/env python
import sys
import re
import time
from optparse import OptionParser
import json
from StringIO import StringIO
import inspect
import doctest


def edit_file_vars(fdin, fdout, vars_dict, file_type, force_add, add_comment = False):
  """ edit variables assignments in config files
  >>> infile = StringIO("#foo=FOO\\nfoonope=0\\n##other\\nbar=BAR\\n")
  >>> outfile = StringIO()
  >>> edit_file_vars(infile, outfile, {'foo': 'f00', 'bar': 'b4R', 'new': 'NEW' }, 'shell', True)
  3
  >>> outfile.getvalue()
  'foo=f00\\nfoonope=0\\n##other\\nbar=b4R\\nnew=NEW\\n'
  >>> infile = StringIO("#foo: FOO\\nfoonope: 0\\n##other\\nbar: BAR\\n")
  >>> outfile = StringIO()
  >>> edit_file_vars(infile, outfile, {'foo': 'f00', 'bar': 'b4R', 'new': 'NEW' }, 'yaml', True)
  3
  >>> outfile.getvalue()
  'foo: f00\\nfoonope: 0\\n##other\\nbar: b4R\\nnew: NEW\\n'
  """
  comment_char = '#'
  assign_res = {
      'yaml' : ['[ ]*:[ ]*', ': ' ],
      'shell' : [ '=', '=' ],
  }

  caller = inspect.stack()[1][1:4]
  try:
    assign_re = assign_res[file_type][0]
  except KeyError, e:
    raise TypeError('Unsupported file_type: %s' % file_type)

  vars_used = []
  lines_modified = 0
  for line in fdin.readlines():
    n = 0
    for var, val in vars_dict.iteritems():
      regex = r'^([%s]*)(\s*)\b(?P<var>%s)\b(?P<ass>%s)\b(?P<sp>\s*)\b(?P<val>[^%s]*)(?P<tail>.*)$' % (comment_char, var, assign_re, comment_char)
      (replaced, n) = re.subn(regex, r'\2\g<var>\g<ass>\g<sp>%s\g<tail>\n' % (val), line)
      if n:
        lines_modified += n
        vars_used.append(var)
        if add_comment:
          fdout.write( "%s Edited by %s on: %s:\n" % (comment_char, caller, time.ctime()))
        fdout.write(replaced)
        break
    if not n:
      fdout.write(line)

  vars_not_used = set(vars_dict.keys()) - set(vars_used)
  if force_add and vars_not_used:
    assign_char = assign_res[file_type][1]
    if add_comment:
      fdout.write( "%s First added by %s on: %s:\n" % (comment_char, caller, time.ctime()))
    for var in list(vars_not_used):
      fdout.write( "%s%s%s\n" % (var, assign_char, vars_dict[var]))
      lines_modified += 1
  return lines_modified


def main():
    parser = OptionParser()
    parser.add_option("-t", "--type", dest="file_type", default='yaml',
                      help="File type for variable replacement, 'shell' or 'yaml'")
    parser.add_option("-j", "--json", dest="json_file",
                      help="JSON formatted file that contains the dictionary to use as var=value")

    (options, args) = parser.parse_args()
    var_dict = json.loads(open(options.json_file).read())
    # Use it as e.g.: %prog -t shell -f <(echo '{ "DISTRIB_ID": "MyOwn" }') < /etc/lsb-release
    edit_file_vars(sys.stdin, sys.stdout, var_dict, options.file_type, False)

if __name__ == '__main__':
    import doctest
    doctest.testmod()
    sys.exit(main())
