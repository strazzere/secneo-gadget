#!/usr/bin/env python3

def find_all(a_str, sub):
    start = 0
    while True:
        start = a_str.find(sub, start)
        if start == -1: return
        yield start
        start += len(sub)

def nuke(fileName):
  fileIn = open(fileName, 'rb')
  data = fileIn.read()
  fileIn.close()
  found = list(find_all(data, b'DexHelper\00c_l_e__check1234567_'))
  if (len(found) != 1):
    print('Expected to find exactly one occurance of bangcle check, found %d' % found)
  data = data.replace(b'DexHelper\00c_l_e__check1234567_', b'__b_a_n_g_c_l_e__check1234567_')
  fileOut = open(fileName + '-fixed', "wb")
  print('Fixed %s and output as %s' % (fileName, fileName + '-fixed'))
  fileOut.write(data)
  fileOut.close()

import sys

if __name__ == '__main__':
  nuke(sys.argv[1])
