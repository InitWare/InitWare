import argparse
import subprocess
import collections
import struct
from systemd import journal

options = argparse.ArgumentParser()
options.add_argument('-H', '--host', default='localhost')
options.add_argument('-p', '--port', default=19531)
options.add_argument('-b', '--boot', default='no',
                     action='store_const', const='yes')
options.add_argument('-f', '--follow', default='no',
                     action='store_const', const='yes')
options.add_argument('-s', '--submit', action='store_true')

def spawn_curl(host, port, boot, follow):
    "Spawn curl to get events from systemd-journal-gatewayd"
    url = 'http://{host}:{port}/entries?follow={follow}&boot={boot}'.format(
        host=host, port=port, follow=follow, boot=boot)
    cmdline = ['curl', '-HAccept: application/vnd.fdo.journal',
               '--silent', '--show-error',
               url]
    child = subprocess.Popen(cmdline,
                             stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE)
    return child

def _read_one(inp):
    fields = collections.OrderedDict()

    while inp:
        line = inp.readline()
        line = line[:-1] # remove newline
        if not line:
            break
        left, split, right = line.partition(b'=')
        name = left.decode('ascii')
        if split:
            value = right.decode()
        else:
            flen_ = inp.read(8)
            flen = struct.unpack('<lL', flen_)[0]
            value = inp.read(flen)
            newline = inp.read(1)
            assert newline == b'\n', newline
            name = name[:-1]
        fields[name] = value

    return fields

def split_stream(stream):
    "Parse journal events from stream"
    while stream:
        fields = _read_one(stream)
        yield fields

def cat_events(stream):
    for event in split_stream(stream):
        print('event MESSAGE=' + event.get('MESSAGE', '(no message)')
              + ' ' + ','.join(event.keys()))

def push_events(stream):
    i = 0
    for event in split_stream(stream):
        #print(event)
        v = [key.encode('utf-8') + b'=' + val
             if isinstance(val, bytes)
             else key + '=' + val
             for key,val in event.items()]
        print('\n'.join(v))
        journal.sendv(*v)
        i += 1
        if i == 1:
                break

if __name__ == '__main__':
    args = options.parse_args()
    curl = spawn_curl(args.host, args.port,
                      args.boot, args.follow)
    if args.submit:
        push_events(curl.stdout)
    else:
        cat_events(curl.stdout)
