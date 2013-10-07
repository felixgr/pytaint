import pipes
import os
import taint

def raw_input():
  # a function which gets something user-supplied from the network, let's use
  # the following string as an example: 'google.com'. If the user would be
  # malicious he could supply a shell injection string like 'google.com;killall
  # python'.
  return 'google.com'

class ShellMerit(Merit):
  '''A string has been cleaned for usage as a shell parameter'''
  propagation = Merit.FullPropagation

taint.enable('example_simple.json')

s = raw_input()
s = pipes.quote(s)  # pipes.quote returns shell escaped version of s
c = 'host ' + s

os.system(c)
