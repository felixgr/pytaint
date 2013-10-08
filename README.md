pytaint
=======
The goal of pytaint project is to provide a taint tracking mechanism for Python
by modifying the CPython interpreter and adding a module with convenience
functions. Taint tracking is a feature which allows to monitor the flow of
untrusted data across the application and preventing from using it in sensitive
parts without proper sanitization.

Compiling & testing
-------------------
Build and test:

    ./configure --with-pydebug && make -j2 && ./python Lib/test/regrtest.py -v

Usage & Examples
----------------
pytaint can be used manually or with a configuration.
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

Alternatively, you can also use pytaint with a configuration which is defined in
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

This program will terminate correctly because the user-supplied input is
sanitized.
However, if the call to `pipes.quote` is removed, it will throw a `TaintError`
exception with an explaination that the string `s` is missing the `ShellMerit`.

### Verbose Example

You can see a practical real world example in
[example_practical.py](example_practical.py).

Design
------

### Background

The motivation for taint tracking is that user data in applications can not be
trusted - for example, a web application user may exploit security
vulnerabilities inside application by supplying malicious data as a form input.
Though user supplied data should be sanitized before using in any sensitive
place, it is often hard to keep a mental model of which data is clean.

The project supplies features that help solve this problem - its features
include:

* marking sources of untrusted data and sensitive data sinks
* tracking untrusted data during runtime and preventing from using it in
  sensitive sinks

Related work:

* Conti introduces a pure Python module with similar capabilities - however
  since he is subclassing every python object, it is really slow
  (http://revista.python.org.ar/1/html-en/taint.html)
* Kozlov and Pethukov provide an interpreter extension that can trace taint
  after execution
  (https://www.owasp.org/images/3/3e/OWASP-AppSecEU08-Petukhov.pdf)
* Russo / Bello's work
* Meder Kydyraliev introduces Gravizapa for Java/Ruby, which inspired some ideas
  in this project (http://www.youtube.com/watch?v=WmZvnKYiNlE)

### Overview

To monitor flow of taint, changes to string and unicode objects are introduced.
Those objects now carry a tainted flag, which indicates if an object comes from
an untrusted source (and therefore can not be trusted). If the flag is set to
true, we call the object tainted and we assume it’s unsafe for any of the
sensitive operations; otherwise, the object is clean and it can be safely used.

Tainted objects propagate taint for all operations (concatenation, splicing,
etc.) - however, they can be sanitized and gain specific security guarantees
called merits. A merit is a guarantee that object is safe for some specific
operation. The merits may be propagated by string operations (specific
propagation rules are explained in a later section of this document).

The extension provides three new kinds of objects:

* sources - functions that return tainted data
* cleaners - functions which can add merits to tainted data
* sinks - function that raise exception when unsafe data is passed to it

The programmer can specify the objects in a configuration file.

It is also possible to give taint information to arbitrary objects by wrapping
them in a Proxy class included in the taint module.

### Detailed Design

#### Key Concepts

A tainted string is a string which contains untrusted data. A clean (untainted)
string is one that programmer can trust. All newly created strings are clean.
Strings created by operations on tainted strings are tainted (see taint
propagation rules).

A merit is a security contract which guarantees that given string may be used
with specific operation. Merits are represented by subclasses of the Merit class
introduced in this project. Each merit specifies one concrete security contract
(example merits may include HTMLMerit, ShellMerit). Merits propagate with
string operations by propagation rules specified in further paragraph. Each
merit should define attribute propagation_rule which is one of
Merit.FullPropagation, Merit.PartialPropagation, Merit.NonePropagation.

A function/method marked as sink(M) for a given merit M will raise
TaintException when a tainted string/unicode (without merit M) will be passed
as an argument to that function.

A function/method marked as cleaner(M) for a given merit M will taint and add
merit M to its return value.

A function/method marked as source will taint its return value (if it is a
string/unicode object - otherwise it will raise a ValueError).

#### Changes to string and unicode objects

String and unicode objects are extended with a taint flag. The tainted strings
also contain information about merits they have gained.

##### New methods

(Everywhere s, t are either string or unicode objects, M is a merit)

* s.taint()  - return a copy of s which is tainted and has no merits
* s.isclean() - return true if s is clean, false if it is tainted
* s.istainted() - return true if s is tainted, false if it is clean
* s.isclean(M) - return false if s is tainted and has no merit M, true otherwise
* s._cleanfor(M) - return copy of s with merit M (if s is clean, the copy will
  be tainted)
* s._merits() - return a set of merits of s, or None if s is clean
* s._propagate(t) - return a copy of s with the same taint flag value and merits
  as string t

Preferably, the programmer should refrain from using those methods - instead a
configuration with cleaners, sinks and sources should be used.

##### Comparison, interning and hashing

Comparison (__eq__) ignores taint and merit information. There are some reasons
why this may be a good idea:

* less refactoring when adding taint to existing code
* taint should be checked by sinks, not by using __eq__
* it won’t lead to confusing bugs where two strings that “print the same” are
  different

Similarly, all strings with the same characters (regardless their taint/merits)
will have the same hash.

With above behaviour it is not clear how (maybe not at all?) tainted strings
should be interned - please see caveats for more information.


#### Builtins

Two builtin objects are introduced:

* TaintException - subclasses StandardError, indicates that a tainted value was
  used in sensitive place
* Merit - subclasses object - an abstract base class for all merits
    * Merit has three inner classes for specifying the propagation -
      FullPropagation, PartialPropagation, NonePropagation
    * Each subclass of Merit should specify attribute propagation_rule (which
      should be one of above)

#### Configuration file and enabling pytaint

The taint tracking should be only active if a configuration file is provided. If
no configuration is provided the python interpreter should perform in the
default way.

The configuration files are stored in JSON. By default, the configuration file
should be called PLUMBING and be stored in the same directory as application
(however, path to other file may be supplied).

```
# note: in a real config file comments are not allowed

{
# a list of sensitive sinks
"sinks" :
  [{"merit" : "MeritA"},
   "mocklib.G",
   "mocklib.F",
   # functions F and G from module mocklib will
   # raise exception when passed a tainted string without MeritA

   {"merit" : "MeritB"},
   "mocklib.F",
   # function F from module mocklib will also
   # raise exception when passed a tainted string without MeritB

   {"merit" : "MeritC"},
   "mocklib.Foo.StaticM",
   "mocklib.Foo.ClassM", "mocklib.Foo.InstanceM",
   # methods StaticM, ClassM and InstanceM from class Foo
   # from module mocklib will raise exception when passed a taint
   # string without MeritC

   # ‘complex’ specification - different checks for each
   # argument:
   {"mocklib.Foo.complicated":
      {"args":
        [{"a" : "HTMLMerit"},
    # first positional argument is checked against HTMLMerit
         "b"
         # second argument may be tainted, taint tracking doesn’t
         # care about it
         {"c" : ["HTMLMerit", "XSSMerit"]}],
         # third argument will be checked against both HTMLMerit and
         # XSSMerit
      "kwargs":
        [{"d" : "HTMLMerit"},
         # keyword argument d is checked against HTMLMerit
         {"e" : "clean"}]}
         # keyword argument e may be tainted, taint tracking doesn’t
         # care about it
   }],
"sources" :
    ["mocklib.F",
     "mocklib.G",
     # functions F and G from module mocklib are taint sources -
     # their return values are tainted
     "mocklib.Foo.StaticM",
     "mocklib.Foo.ClassM",
     "mocklib.Foo.InstanceM"
     # methods StaticM, ClassM and InstanceM of class Foo from module
     # mocklib are now also taint sources
    ],
"cleaners" :
    [{"merit" : "HTMLMerit"},
     "mod.C.m",
     "mod.C.IC.m",
     # methods m from class C from module mod and m from inner class
     # IC of class C from module mod are cleaners for HTMLMerit -
     # their return values will have HTMLMerit

    {"merit" : "ShellMerit"},
     "pipes.quote"
     # method quote from module pipes is cleaner for the ShellMerit
    ]
}
```

#### Merits and taint propagation

##### Taint propagation

Taint is propagated by following operations:

capitalize, expandtabs, ljust, splitlines, upper, center, lower, rjust, zfill,
format, lstrip, rpartition, strip, decode, partition, rsplit, swapcase, encode,
replace, rstrip, title, join, split), splicing ( [ ] ), concatenation (+),
repeating (*), formatting (%)

Ie. if one of the arguments is tainted, the result will also be tainted.

##### Merit propagation

Merits are propagated by the same string operations as taint, however
propagation of them is more complicated. Depending on the value of attribute
propagation_rule, there are three types of merit propagation. For each of them,
I give an example of how merit is propagated for a two argument operation -
these behaviours can be easily generalised for N-argument operations (for one
argument operation, the taint status and set of merits stay the same). (Also,
all we assume that all string operations are commutative when it comes to
propagation).

###### FullPropagation

| first argument | second argument | result |
| -------------- | --------------- | ------ |
| has merit M | is clean | has merit M |
| has merit M | has merit M | has merit M |
| has merit M | is tainted, has no merit M | is tainted (no merit M) |

###### PartialPropagation

| first argument | second argument | result |
| -------------- | --------------- | ------ |
| has merit M | is clean | is tainted (no merit M) |
| has merit M | has merit M | has merit M |
| has merit M | is tainted, has no merit M | is tainted (no merit M) |

###### NonePropagation

| first argument | second argument | result |
| -------------- | --------------- | ------ |
| has merit M | is clean | is tainted (no merit M) |
| has merit M | has merit M | is tainted (no merit M) |
| has merit M | is tainted, has no merit M | is tainted (no merit M) |

#### Taint module contents

##### Merits
For programmers’ convenience, most commonly used merits will be introduced in
this module.

##### Context managers

Context managers to locally alter the merits’ propagation level are introduced:

* unsafePropagationFull(MeritM) - inside this context MeritM will propagate by
  FullPropagation rule
* unsafePropagationPartial(MeritM) - inside this context MeritM will propagate
  by PartialPropagation rule
* unsafePropagationNone(MeritM) - inside this context MeritM will propagate by
  NonePropagation rule

Note that context managers may introduce vulnerabilities, and using them
indicates places which should be carefully reviewed.

##### Decorators
The module contains decorators to create sinks, sources and cleaners. However,
they are mostly for testing/debug purposes; instead a config file should be
used.

Included decorators:

* source - create a taint source
* sink(MeritM) - create a sink checking for merit MeritM
* cleaner(MeritM) - create a cleaner cleaning for MeritM
* propagator - turns a class or function into a taint propagator
  (see below for more details)

##### Tainting builtin collections

The sink and propagators will also attempt tainting builtin collections of
strings/unicodes. Each element of the collections will be tainted recursively
 For dictionaries, only values are tainted.

##### Propagator wrappers

The taint module allows to give taint tracking capabilities to arbitrary
classes. Ways to do it are:

* propagator decorator
* specifying propagators in config (similarly to sinks)
  (this is basically listing in a separate file what should be
  decorated)
* Propagator proxy

The propagator decorator will attempt recognizing whether decorated object is a
function or a class. If it is a function, during each call taint will be
propagated form its arguments and then assigned to result - if the result will
be tainted (possibly a non string object may be tainted in this way). If it is a
class, it will be wrapped in a Propagator proxy.

Propagator proxy can be used to add taint propagation to an arbitrary class. If
this is the case, the taint will be collected from the constructor’s argument on
initialization, and assigned to __taint variable. All the methods will propagate
taint between this variable and their arguments and taint result accordingly
(wrapping it with the same class).

Note: objects of builtin types (int, float, bool, None, str, unicode and builtin
collections) are not wrapped by those mechanisms. str and unicode are tainted by
their builtin methods. Builtin collections are tainted as described in previous
sections of this document.

##### Other

taint.Enable(filename=PLUMBING) - enable taint tracking using rules in supplied
configuration file (filename). This function monkey patches functions/methods
specified in configuration files and should be called after all imports are
done.

### Caveats

#### No control flow analysis

A tainted string may be used to check a condition in if expression without
raising any issues. These means that unsafe data may affect control flow. One
way to prevent that is to create a sink of checked expression in use it in if
condition instead.

#### Serialisation

It is not possible to save taint data into non-python formats without
introducing some convention for storing it - therefore taint data is stripped
when serializing objects (to for example JSON or BlobStore).

#### String interning and hashes

Since tainted strings have the same hashes as their clean equivalents,
introducing taint mechanism would require changing the interning behaviour.
Considered solutions:

* don’t intern tainted data
* ‘cheat’ the interning dictionary by providing fake hashing function when
  interning tainted strings

It is also not quite clear if giving the different hash to ‘same’ strings is a
good idea - for example, this could potentially make dictionaries unusable (ie.
retrieving a value stored with a tainted key could be difficult).

#### Configuration hierarchy

At the moment, each application uses its own configuration file. However, when
different application use the same library, we probably want this library to
have similar (the same) taint tracking configuration. At the moment, it is
possible to read multiple taint configurations at the application startup (which
will result in applying all of them), however this doesn’t seem like a very good
solution.

#### Propagation through other modules

Intuitively, it seems obvious that some modules (for example, re) should
propagate taint information. This would require additional changes in those
modules.

Authors
-------
Marcin Fatyga wrote pytaint during his internship at Google,
supervised by [Felix Groebert](http://twitter.com/fel1x).
Big thanks to Torsten Marek, Gregory P. Smith and Thomas Wouters for valuable
feedback.
