pytaint
=======
The goal of pytaint project is providing a taint tracking mechanism for Python
by modifying the CPython interpreter and adding a module with convenience
functions. Taint tracking is a feature which allows to monitor the flow of
untrusted data across the application and preventing from using it in sensitive
parts without proper sanitization.

Compiling & testing
-------------------
Build and test:

    ./configure --with-pydebug && make -j2 && ./python Lib/test/regrtest.py -v

Usage
-----
pytaint can be used manually or using a configuration.
Let's look at manual usage first:

### Manual Usage

```python
# merit is a 'security contract'
# each merit indicates that the object is safe for some specific operation

s = "foo"
assert s.istainted() == False

s = s.taint()
assert s.istainted() == True

# all operations on tainted objects result in tainted objects
s = s.upper()
assert s.istainted() == True

# let's do some more string operations...
# merits also propagate in string operations
p = "bar"
r = s + p

# p has never been tainted, so it's clean
assert p.isclean(SQLiMerit) == True

# a tainted string can gain merits
s = s._cleanfor(SQLiMerit)
s = s._cleanfor(ShellMerit)
assert s.isclean(SQLiMerit) == True

# r is a concatenation of a tainted (without any merits) and a untainted string
assert r.isclean(SQLiMerit) == False
```

### Configured Usage

Alternatively you can also use pytaint with a configuration which is defined in
JSON:

```json
{
  "cleaners": [
    {"merit": "ShellMerit"},
     "pipes.quote"],
  "sinks": [
    {"merit": "ShellMerit"},
     "os.system"],
  "sources": [
    "raw_input"]
}
```

Configurations easily let you adapt and manage your taint logic.
Consider the above configuration used with the program below.

```python
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
```

This program will work well because the user supplied input is sanitized.
However, if the call to `pipes.quote` is removed, it will throw a `TaintError`
exception with an explaination that the string `s` is missing the `ShellMerit`.

### Verbose Example

You can see a practical real world example in
[example_practical.*][example_practica.py].

Authors
-------
Marcin Fatyga wrote pytaint during his internship at Google, supervised by [Felix
Groebert](http://twitter.com/fel1x).
Big thanks to Torsten Marek, Gregory P. Smith and Thomas Wouters for valuable
feedback.
