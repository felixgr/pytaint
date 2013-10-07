import unittest
import itertools
import taint
import json
import imp
import re
from test import test_support

CONFIG_1 = test_support.findfile('config1.json', subdir='tainttestdata')
CONFIG_2 = test_support.findfile('config2.json', subdir='tainttestdata')
CONFIG_3 = test_support.findfile('config3.json', subdir='tainttestdata')
CONFIG_4 = test_support.findfile('config4.json', subdir='tainttestdata')

BROKEN_SMALL = test_support.findfile('config_broken_small.json',
                                     subdir='tainttestdata')
BROKEN_BIG = test_support.findfile('config_broken_big.json',
                                   subdir='tainttestdata')

MOCK_MODULE_FILE = test_support.findfile('mockmodule.py',
                                         subdir='tainttestdata')
MockModule = imp.load_source('MockModule', MOCK_MODULE_FILE)

class MeritFull(Merit):
    propagation = Merit.FullPropagation

class MeritPart(Merit):
    propagation = Merit.PartialPropagation

class MeritNone(Merit):
    propagation = Merit.NonePropagation

class AbstractTaintTest(unittest.TestCase):
    def assertTainted(self, object):
        self.assertTrue(object.istainted())
        self.assertFalse(object.isclean())

    def assertClean(self, object):
        self.assertTrue(object.isclean())
        self.assertFalse(object.istainted())

    def assertMerits(self, object, merits):
        if merits == None or object._merits() == None:
            self.assertEqual(object._merits(), None)
            self.assertEqual(merits, None)
            self.assertClean(object)
        else:
            self.assertEqual(object._merits(), set(merits))

    def assertTaintedAll(self, object):
        for o in object:
            self.assertTainted(o)

    def assertCleanAll(self, object):
        for o in object:
            self.assertClean(o)

    def assertMeritsAll(self, object, merits):
        for o in object:
            self.assertMerits(o, merits)

    def assertMeritsAllGroups(self, object, merits):
        for o in object:
            self.assertMeritsAll(o.groupdict().values(), merits)

# Though decorators are not encouraged way of using this module, the patching
# module works by decorating functions specified in config, so it makes sense
# to have (and test them) anyway.

class DecoratorTest(AbstractTaintTest):
    def test_simple_functions(self):
        @taint.source
        def src():
            return "abc"

        @taint.source
        def src2():
            return ["abc", "def", "xyz"]

        @taint.source
        def src3():
            return ("abc", "def", ("xyz", "tw"))

        @taint.source
        def src4():
          return {1: ["aaa", "bbb"],
                  3: ("ccc", "ddd")}

        @taint.cleaner(MeritFull)
        def cln(s):
            return s

        @taint.sink(MeritFull)
        def snk(s):
            return True

        def flatten(l):
            return itertools.chain.from_iterable(l)

        s = src()
        self.assertTainted(s)
        for s in src2():
            self.assertTainted(s)
        for s in flatten(src3()):
            self.assertTainted(s)
        for s in flatten(src4().values()):
            self.assertTainted(s)

        c = cln(s)
        self.assertTainted(c)
        self.assertMerits(c, [MeritFull])
        self.assertTrue(snk(c))

        with self.assertRaises(TaintError):
            snk(s)

        with self.assertRaises(TaintError):
            snk('abc'.taint())

        self.assertTrue(snk('abc'))


class SimplePatcherTest(AbstractTaintTest):
    class InnerClass(object):
        @staticmethod
        def static_source():
            return "abc"

        @staticmethod
        def static_cleaner(s):
            return s

        @staticmethod
        def static_sink(s):
            return True

        @classmethod
        def class_source(cls):
            return "abc"

        @classmethod
        def class_cleaner(cls, s):
            return s


        @classmethod
        def class_sink(cls, s):
            return True

        def instance_source(self):
            return "abc"

        def instance_cleaner(self, s):
            return s

        def complex_sink(self, a, b, c, d=None, e=None, f=None):
            return True

        def instance_sink(self, s):
            return True


    def test_patcher_classes(self):
        self.assertTainted(SimplePatcherTest.InnerClass.static_source())
        with self.assertRaises(TaintError):
            SimplePatcherTest.InnerClass.static_sink('a'.taint())
        self.assertTrue(SimplePatcherTest.InnerClass.static_sink('a'))

        self.assertTainted(SimplePatcherTest.InnerClass.class_source())
        with self.assertRaises(TaintError):
            SimplePatcherTest.InnerClass.class_sink('a'.taint())
        self.assertTrue(SimplePatcherTest.InnerClass.class_sink('a'))

        inc = SimplePatcherTest.InnerClass()
        self.assertTainted(inc.instance_source())
        with self.assertRaises(TaintError):
            inc.instance_sink('a'.taint())
        self.assertTrue(inc.instance_sink('a'))
        self.assertMerits(inc.instance_cleaner('a'.taint()),
                          [MeritFull, MeritNone])

    def test_patcher_toplevel(self):
        self.assertTainted(toplevel_source())
        with self.assertRaises(TaintError):
            toplevel_sink('a'.taint())


    def test_complex_patching(self):
        inc = SimplePatcherTest.InnerClass()
        self.assertTainted(inc.instance_source())
        with self.assertRaises(TaintError):
            inc.complex_sink('a'.taint(), 'b', 'c', d='d', e='e')
        with self.assertRaises(TaintError):
            inc.complex_sink('a'._cleanfor(MeritFull), 'b',
                             'c'._cleanfor(MeritFull), d='d',
                             e='e'._cleanfor(MeritFull))
        self.assertTrue(inc.complex_sink('a', 'b', 'c', d='d', e='e'))
        with self.assertRaises(TaintError):
            inc.complex_sink('a'._cleanfor(MeritFull)._cleanfor(MeritNone), 'b',
                             'c'._cleanfor(MeritFull), d='d',
                             e='e'._cleanfor(MeritFull)._cleanfor(MeritNone))
        self.assertTrue(inc.complex_sink(
                            'a'._cleanfor(MeritFull)._cleanfor(MeritNone),
                            'b',
                            'c'._cleanfor(MeritFull)._cleanfor(MeritNone),
                            d='d',
                            e='e'._cleanfor(MeritFull)._cleanfor(MeritNone)))
        self.assertTrue(inc.complex_sink('a', 'b', 'c', d='d', e='e',
                                         f={'foo': 'bar'}))
        with self.assertRaises(TaintError):
            inc.complex_sink('a', 'b', 'c', d='d', e='e',
                             f={'foo': 'bar'.taint()})
        self.assertTrue(inc.complex_sink('a', 'b', 'c', d='d', e='e',
                                         f={'foo':
                                            'bar'._cleanfor(MeritFull)\
                                                 ._cleanfor(MeritNone)}))

class ImportedObjectsPatchingTest(AbstractTaintTest):
    def setUp(self):
        taint.enable(CONFIG_2)

    def testImportedPatching(self):
        inc = MockModule.MockClass()
        self.assertTainted(inc.instance_source())
        with self.assertRaises(TaintError):
            inc.instance_sink('a'.taint())
        self.assertTrue(inc.instance_sink('a'))
        self.assertMerits(inc.instance_cleaner('a'.taint()),
                          [MockModule.MeritX])


class PropagationContextsTest(AbstractTaintTest):
    def testContexts(self):
        ut = 'ttt'
        tt = 'ttt'
        tf = 'ttt'._cleanfor(MeritFull)
        tp = 'ttt'._cleanfor(MeritPart)
        tn = 'ttt'._cleanfor(MeritNone)

        with taint.unsafePropagationFull(MeritNone):
            self.assertMerits(ut + tn, [MeritNone])
            self.assertMerits(tn + tn, [MeritNone])

        with taint.unsafePropagationNone(MeritFull):
            self.assertMerits(ut + tf, [])
            self.assertMerits(tf + tf, [])

        with taint.unsafePropagationPartial(MeritNone):
            self.assertMerits(tn + tn, [MeritNone])
            self.assertMerits(ut + tn, [])


class ConfigValidation(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None

    def test_validator_errors_small(self):
        config = json.load(open(BROKEN_SMALL, "r"))
        warnings, errors = taint.Validator(config).validate()
        errors_expected = [
           "Malformed sources in the taint config (expected a list, not"
           " <type 'unicode'>)",
           "Malformed cleaners in the taint config (expected a list, not"
           " <type 'unicode'>)",
           "Malformed sinks in the taint config (expected a list, not"
           " <type 'unicode'>)",
        ]
        warnings_expected = []
        self.assertItemsEqual(warnings, warnings_expected)
        self.assertItemsEqual(errors, errors_expected)

    def test_validator_errors_big(self):
        config = json.load(open(BROKEN_BIG, "r"))
        warnings, errors = taint.Validator(config).validate()
        warnings = map(unicode, warnings)
        errors = map(unicode, errors)
        errors_expected = [
            u"No merit specified for cleaner cleaner_f.",
            u"No merit specified for sink function_f.",
            u"Unexpected object in cleaners: [].",
            u"Unexpected object in sinks: [u'unexpected', u'object'].",

            # broken complex sink errors:
            u"Malformed args (expected list) for complex sink complex_sink_3.",
            u"Malformed kwargs (expected list) for complex sink"
            " complex_sink_4.",
            u"Malformed (keyword or positional) argument [u'qwer'] in complex"
            " sink complex_sink_5.",
            u"Malformed (keyword or positional) argument {} in complex sink"
            " complex_sink_6.",
            u"Malformed merits 1234 for argument aaa in complex sink"
            " complex_sink_7.",
            u"Malformed merits [5] for argument bbb in complex sink"
            " complex_sink_8.",

            # broken complex sinks:
            u"Unexpected object in sinks: {u'complex_sink_3':"
            " {u'args': u'zxcv'}}.",
            u"Unexpected object in sinks: {u'complex_sink_4':"
            " {u'kwargs': u'zxcv'}}.",
            u"Unexpected object in sinks: {u'complex_sink_5':"
            " {u'kwargs': [[u'qwer']]}}.",
            u"Unexpected object in sinks: {u'complex_sink_6':"
            " {u'kwargs': [{}]}}.",
            u"Unexpected object in sinks: {u'complex_sink_7':"
            " {u'kwargs': [{u'aaa': 1234}]}}.",
            u"Unexpected object in sinks: {u'complex_sink_8':"
            " {u'kwargs': [{u'bbb': [5]}]}}."
        ]

        warnings_expected = [
            u"Unexpected fields in config: bar, baz, foo.",
            u"No cleaners specified for merit MeritA.",
            u"No cleaners specified for merit MeritC.",
            u"No sinks specified for merit MeritD.",
            u"Config may be confusing - simple sink function_g is preceded by"
            " a complex sink, not simple sink or merit.",
            u"Config may be confusing - complex sink complex_sink preceded"
            " by a merit MeritE, not another sink.",
            u"No sinks specified for merit MeritF.",
            u"Unexpected options: bar, foo",

            u"Unexpected key in complex_sink_2: foobar.",
        ]

        self.assertItemsEqual(warnings, warnings_expected)
        self.assertItemsEqual(errors, errors_expected)


class PropagatorTest(AbstractTaintTest):
    class Person(object):
        def __init__(self, name):
            self.name = name

        def rename(self, name):
            self.name = name

        def greet(self, greeting):
            return "{}, {}!".format(greeting,
                                    self.name)
        def duplicate(self):
            return PropagatorTest.Person(self.name)

    def setUp(self):
        taint.enable(CONFIG_3)

    def test_propagator_decoration(self):
        @taint.propagator
        class Person2():
            def __init__(self, name):
                self.name = name

            def rename(self, name):
                self.name = name

            def greet(self, greeting):
                return "{}, {}!".format(greeting,
                                        self.name)
            def duplicate(self):
                return Person2(self.name)

        @taint.propagator
        def const2(s):
            return "abc"

        self.assertClean(const2("abc"))
        self.assertTainted(const2("abc".taint()))
        self.assertMerits(const2("abc"._cleanfor(MeritNone)), [MeritNone])
        pu = Person2("xyz")
        p_none = Person2("xyz"._cleanfor(MeritNone))
        p_part = Person2("xyz"._cleanfor(MeritPart))
        p_full = Person2("xyz"._cleanfor(MeritFull))

        self.assertMerits(pu.name, None)
        self.assertMerits(p_none.name, [MeritNone])
        self.assertMerits(p_part.name, [MeritPart])
        self.assertMerits(p_full.name, [MeritFull])

        self.assertMerits(pu.greet("hi"), None)
        self.assertMerits(p_none.greet("hi"), [])
        self.assertMerits(p_part.greet("hi"), [])
        self.assertMerits(p_full.greet("hi"), [MeritFull])

        self.assertMerits(pu.greet("hi".taint()), [])
        self.assertMerits(p_none.greet("hi".taint()), [])
        self.assertMerits(p_part.greet("hi".taint()), [])
        self.assertMerits(p_full.greet("hi".taint()), [])

        self.assertMerits(pu.duplicate().name, None)
        self.assertMerits(p_none.duplicate().name, [])
        self.assertMerits(p_part.duplicate().name, [])
        self.assertMerits(p_full.duplicate().name, [MeritFull])

    def test_propagator_config(self):
        self.assertClean(toplevel_propagator("abc"))
        self.assertTainted(toplevel_propagator("abc".taint()))
        self.assertMerits(toplevel_propagator("abc"._cleanfor(MeritNone)),
                          [MeritNone])

        pu = PropagatorTest.Person("xyz")
        p_none = PropagatorTest.Person("xyz"._cleanfor(MeritNone))
        p_part = PropagatorTest.Person("xyz"._cleanfor(MeritPart))
        p_full = PropagatorTest.Person("xyz"._cleanfor(MeritFull))

        self.assertMerits(pu.name, None)
        self.assertMerits(p_none.name, [MeritNone])
        self.assertMerits(p_part.name, [MeritPart])
        self.assertMerits(p_full.name, [MeritFull])

        self.assertMerits(pu.greet("hi"), None)
        self.assertMerits(p_none.greet("hi"), [])
        self.assertMerits(p_part.greet("hi"), [])
        self.assertMerits(p_full.greet("hi"), [MeritFull])

        self.assertMerits(pu.greet("hi".taint()), [])
        self.assertMerits(p_none.greet("hi".taint()), [])
        self.assertMerits(p_part.greet("hi".taint()), [])
        self.assertMerits(p_full.greet("hi".taint()), [])

        self.assertMerits(pu.duplicate().name, None)
        self.assertMerits(p_none.duplicate().name, [])
        self.assertMerits(p_part.duplicate().name, [])
        self.assertMerits(p_full.duplicate().name, [MeritFull])

    def test_taint_object_function(self):
        class Person2():
            def __init__(self, name):
                self.name = name

            def greet(self, greeting):
                return "{}, {}!".format(greeting,
                                        self.name)
            def duplicate(self):
                return Person2(self.name)

        class Dict(dict): pass
        class List(list): pass
        class Tuple(tuple): pass
        class Set(set): pass
        class FrozenSet(frozenset): pass

        pu = taint._taint_object(Person2("xyz"), None)
        p_none = taint._taint_object(Person2("xyz"), [MeritNone])
        p_part = taint._taint_object(Person2("xyz"), [MeritPart])
        p_full = taint._taint_object(Person2("xyz"), [MeritFull])

        self.assertMerits(pu.name, None)
        self.assertMerits(p_none.name, [MeritNone])
        self.assertMerits(p_part.name, [MeritPart])
        self.assertMerits(p_full.name, [MeritFull])

        self.assertMerits(pu.greet("hi"), None)
        self.assertMerits(p_none.greet("hi"), [])
        self.assertMerits(p_part.greet("hi"), [])
        self.assertMerits(p_full.greet("hi"), [MeritFull])

        self.assertMerits(pu.greet("hi".taint()), [])
        self.assertMerits(p_none.greet("hi".taint()), [])
        self.assertMerits(p_part.greet("hi".taint()), [])
        self.assertMerits(p_full.greet("hi".taint()), [])

        self.assertMerits(pu.duplicate().name, None)
        self.assertMerits(p_none.duplicate().name, [])
        self.assertMerits(p_part.duplicate().name, [])
        self.assertMerits(p_full.duplicate().name, [MeritFull])

        for Cls in [List, Tuple, Set, FrozenSet]:
            x = Cls("a")
            self.assertMeritsAll(taint._taint_object(x, [MeritFull]),
                                 [MeritFull])
            for item in taint._taint_object(x, None):
                self.assertClean(item)

        d = Dict()
        d["a"] = "b"
        self.assertMeritsAll(taint._taint_object(d, [MeritFull]).values(),
                             [MeritFull])

class OptionsTest(AbstractTaintTest):
    def setUp(self):
        taint.enable(CONFIG_4)

    def test_file_handles(self):
        def fake_open(name):
            class File():
                def __init__(self, name):
                    self.name = name

                def read(self):
                    return "qwerty"

            return File(name)

        # mock the open(), because patching it will mess up other tests
        globals()["fake_open"] = taint._proxy_function(fake_open,
                                                       tainted=True)


    def test_search(self):
        ut = "abc"
        tt = ut.taint()
        t_full = ut._cleanfor(MeritFull)
        t_part = ut._cleanfor(MeritPart)
        t_none = ut._cleanfor(MeritNone)
        t_all = ut._cleanfor(MeritFull)._cleanfor(MeritPart)\
                  ._cleanfor(MeritNone)

        self.assertTainted(re.search(tt, tt).group(0))
        self.assertTainted(re.search(tt, ut).group(0))
        self.assertTainted(re.search(ut, tt).group(0))
        # Note: the order of this tests matter, since we want to
        # make sure we did not break caching
        self.assertClean(re.search(ut, ut).group(0))

        self.assertMerits(re.search(ut, tt).group(0), [])
        self.assertMerits(re.search(ut, t_all).group(0), [MeritFull])
        self.assertMerits(re.search(ut, t_full).group(0), [MeritFull])
        self.assertMerits(re.search(ut, t_part).group(0), [])
        self.assertMerits(re.search(ut, t_none).group(0), [])

        self.assertMerits(re.search(tt, ut).group(0), [])
        self.assertMerits(re.search(t_all, ut).group(0), [MeritFull])
        self.assertMerits(re.search(t_full, ut).group(0), [MeritFull])
        self.assertMerits(re.search(t_part, ut).group(0), [])
        self.assertMerits(re.search(t_none, ut).group(0), [])

        self.assertMerits(re.search(t_all, tt).group(0), [])
        self.assertMerits(re.search(t_all, t_full).group(0), [MeritFull])
        self.assertMerits(re.search(t_all, t_part).group(0), [])
        self.assertMerits(re.search(t_all, t_none).group(0), [])

        self.assertMerits(re.search(tt, t_all).group(0), [])
        self.assertMerits(re.search(t_full, t_all).group(0), [MeritFull])
        self.assertMerits(re.search(t_part, t_all).group(0), [])
        self.assertMerits(re.search(t_none, t_all).group(0), [])

    def test_match(self):
        ut = "abc"
        tt = ut.taint()
        t_full = ut._cleanfor(MeritFull)
        t_part = ut._cleanfor(MeritPart)
        t_none = ut._cleanfor(MeritNone)
        t_all = ut._cleanfor(MeritFull)._cleanfor(MeritPart)\
                  ._cleanfor(MeritNone)

        self.assertTainted(re.match(tt, tt).group(0))
        self.assertTainted(re.match(tt, ut).group(0))
        self.assertTainted(re.match(ut, tt).group(0))
        # the order of this tests matter, since we want to
        # make sure we did not break caching
        self.assertClean(re.match(ut, ut).group(0))

        self.assertMerits(re.match(ut, tt).group(0), [])
        self.assertMerits(re.match(ut, t_all).group(0), [MeritFull])
        self.assertMerits(re.match(ut, t_full).group(0), [MeritFull])
        self.assertMerits(re.match(ut, t_part).group(0), [])
        self.assertMerits(re.match(ut, t_none).group(0), [])

        self.assertMerits(re.match(tt, ut).group(0), [])
        self.assertMerits(re.match(t_all, ut).group(0), [MeritFull])
        self.assertMerits(re.match(t_full, ut).group(0), [MeritFull])
        self.assertMerits(re.match(t_part, ut).group(0), [])
        self.assertMerits(re.match(t_none, ut).group(0), [])

        self.assertMerits(re.match(t_all, tt).group(0), [])
        self.assertMerits(re.match(t_all, t_full).group(0), [MeritFull])
        self.assertMerits(re.match(t_all, t_part).group(0), [])
        self.assertMerits(re.match(t_all, t_none).group(0), [])

        self.assertMerits(re.match(tt, t_all).group(0), [])
        self.assertMerits(re.match(t_full, t_all).group(0), [MeritFull])
        self.assertMerits(re.match(t_part, t_all).group(0), [])
        self.assertMerits(re.match(t_none, t_all).group(0), [])

    def test_sub(self):
        ut = "abc"
        tt = ut.taint()
        t_full = ut._cleanfor(MeritFull)
        t_part = ut._cleanfor(MeritPart)
        t_none = ut._cleanfor(MeritNone)
        t_all = ut._cleanfor(MeritFull)._cleanfor(MeritPart)\
                  ._cleanfor(MeritNone)

        self.assertTainted(re.sub(tt, tt, tt))
        self.assertTainted(re.sub(tt, tt, ut))
        self.assertTainted(re.sub(tt, ut, tt))
        self.assertTainted(re.sub(ut, tt, tt))
        self.assertTainted(re.sub(ut, ut, tt))
        self.assertTainted(re.sub(ut, tt, ut))
        self.assertTainted(re.sub(tt, ut, ut))
        # the order of this tests matter, since we want to
        # make sure we did not break caching
        self.assertClean(re.sub(ut, ut, ut))

        self.assertMerits(re.sub(ut, ut, tt), [])
        self.assertMerits(re.sub(ut, ut, t_all), [MeritFull])
        self.assertMerits(re.sub(ut, ut, t_full), [MeritFull])
        self.assertMerits(re.sub(ut, ut, t_part), [])
        self.assertMerits(re.sub(ut, ut, t_none), [])

        self.assertMerits(re.sub(ut, tt, ut), [])
        self.assertMerits(re.sub(ut, t_all, ut), [MeritFull])
        self.assertMerits(re.sub(ut, t_full, ut), [MeritFull])
        self.assertMerits(re.sub(ut, t_part, ut), [])
        self.assertMerits(re.sub(ut, t_none, ut), [])

        self.assertMerits(re.sub(tt, ut, ut), [])
        self.assertMerits(re.sub(t_all, ut, ut), [MeritFull])
        self.assertMerits(re.sub(t_full, ut, ut), [MeritFull])
        self.assertMerits(re.sub(t_part, ut, ut), [])
        self.assertMerits(re.sub(t_none, ut, ut), [])

        self.assertMerits(re.sub(t_all, t_all, tt), [])
        self.assertMerits(re.sub(t_all, t_all, ut), [MeritFull])
        self.assertMerits(re.sub(t_all, t_all, t_full), [MeritFull])
        self.assertMerits(re.sub(t_all, t_all, t_part), [MeritPart])
        self.assertMerits(re.sub(t_all, t_all, t_none), [])

        self.assertMerits(re.sub(t_all, tt, t_all), [])
        self.assertMerits(re.sub(t_all, ut, t_all), [MeritFull])
        self.assertMerits(re.sub(t_all, t_full, t_all), [MeritFull])
        self.assertMerits(re.sub(t_all, t_part, t_all), [MeritPart])
        self.assertMerits(re.sub(t_all, t_none, t_all), [])

        self.assertMerits(re.sub(tt, t_all, t_all), [])
        self.assertMerits(re.sub(ut, t_all, t_all), [MeritFull])
        self.assertMerits(re.sub(t_full, t_all, t_all), [MeritFull])
        self.assertMerits(re.sub(t_part, t_all, t_all), [MeritPart])
        self.assertMerits(re.sub(t_none, t_all, t_all), [])

    def test_subn(self):
        ut = "abc"
        tt = ut.taint()
        t_full = ut._cleanfor(MeritFull)
        t_part = ut._cleanfor(MeritPart)
        t_none = ut._cleanfor(MeritNone)
        t_all = ut._cleanfor(MeritFull)._cleanfor(MeritPart)\
                  ._cleanfor(MeritNone)

        self.assertTainted(re.subn(tt, tt, tt)[0])
        self.assertTainted(re.subn(tt, tt, ut)[0])
        self.assertTainted(re.subn(tt, ut, tt)[0])
        self.assertTainted(re.subn(ut, tt, tt)[0])
        self.assertTainted(re.subn(ut, ut, tt)[0])
        self.assertTainted(re.subn(ut, tt, ut)[0])
        self.assertTainted(re.subn(tt, ut, ut)[0])
        # the order of this tests matter, since we want to
        # make sure we did not break caching
        self.assertClean(re.subn(ut, ut, ut)[0])

        self.assertMerits(re.subn(ut, ut, tt)[0], [])
        self.assertMerits(re.subn(ut, ut, t_all)[0], [MeritFull])
        self.assertMerits(re.subn(ut, ut, t_full)[0], [MeritFull])
        self.assertMerits(re.subn(ut, ut, t_part)[0], [])
        self.assertMerits(re.subn(ut, ut, t_none)[0], [])

        self.assertMerits(re.subn(ut, tt, ut)[0], [])
        self.assertMerits(re.subn(ut, t_all, ut)[0], [MeritFull])
        self.assertMerits(re.subn(ut, t_full, ut)[0], [MeritFull])
        self.assertMerits(re.subn(ut, t_part, ut)[0], [])
        self.assertMerits(re.subn(ut, t_none, ut)[0], [])

        self.assertMerits(re.subn(tt, ut, ut)[0], [])
        self.assertMerits(re.subn(t_all, ut, ut)[0], [MeritFull])
        self.assertMerits(re.subn(t_full, ut, ut)[0], [MeritFull])
        self.assertMerits(re.subn(t_part, ut, ut)[0], [])
        self.assertMerits(re.subn(t_none, ut, ut)[0], [])

        self.assertMerits(re.subn(t_all, t_all, tt)[0], [])
        self.assertMerits(re.subn(t_all, t_all, ut)[0], [MeritFull])
        self.assertMerits(re.subn(t_all, t_all, t_full)[0], [MeritFull])
        self.assertMerits(re.subn(t_all, t_all, t_part)[0], [MeritPart])
        self.assertMerits(re.subn(t_all, t_all, t_none)[0], [])

        self.assertMerits(re.subn(t_all, tt, t_all)[0], [])
        self.assertMerits(re.subn(t_all, ut, t_all)[0], [MeritFull])
        self.assertMerits(re.subn(t_all, t_full, t_all)[0], [MeritFull])
        self.assertMerits(re.subn(t_all, t_part, t_all)[0], [MeritPart])
        self.assertMerits(re.subn(t_all, t_none, t_all)[0], [])

        self.assertMerits(re.subn(tt, t_all, t_all)[0], [])
        self.assertMerits(re.subn(ut, t_all, t_all)[0], [MeritFull])
        self.assertMerits(re.subn(t_full, t_all, t_all)[0], [MeritFull])
        self.assertMerits(re.subn(t_part, t_all, t_all)[0], [MeritPart])
        self.assertMerits(re.subn(t_none, t_all, t_all)[0], [])

    def test_split(self):
        ut = "abc"
        tt = ut.taint()
        t_full = ut._cleanfor(MeritFull)
        t_part = ut._cleanfor(MeritPart)
        t_none = ut._cleanfor(MeritNone)
        t_all = ut._cleanfor(MeritFull)._cleanfor(MeritPart)\
                  ._cleanfor(MeritNone)

        self.assertTaintedAll(re.split(tt, tt[0]))
        self.assertTaintedAll(re.split(tt, ut[0]))
        self.assertTaintedAll(re.split(ut, tt[0]))
        # the order of this tests matter, since we want to
        # make sure we did not break caching
        self.assertCleanAll(re.split(ut, ut[0]))

        self.assertMeritsAll(re.split(ut, tt[0]), [])
        self.assertMeritsAll(re.split(ut, t_all[0]), [MeritFull])
        self.assertMeritsAll(re.split(ut, t_full[0]), [MeritFull])
        self.assertMeritsAll(re.split(ut, t_part[0]), [])
        self.assertMeritsAll(re.split(ut, t_none[0]), [])

        self.assertMeritsAll(re.split(tt, ut[0]), [])
        self.assertMeritsAll(re.split(t_all, ut[0]), [MeritFull])
        self.assertMeritsAll(re.split(t_full, ut[0]), [MeritFull])
        self.assertMeritsAll(re.split(t_part, ut[0]), [])
        self.assertMeritsAll(re.split(t_none, ut[0]), [])

        self.assertMeritsAll(re.split(t_all, tt[0]), [])
        self.assertMeritsAll(re.split(t_all, t_full[0]), [MeritFull])
        self.assertMeritsAll(re.split(t_all, t_part[0]), [MeritPart])
        self.assertMeritsAll(re.split(t_all, t_none[0]), [])

        self.assertMeritsAll(re.split(tt, t_all[0]), [])
        self.assertMeritsAll(re.split(t_full, t_all[0]), [MeritFull])
        self.assertMeritsAll(re.split(t_part, t_all[0]), [MeritPart])
        self.assertMeritsAll(re.split(t_none, t_all[0]), [])

    def test_findall(self):
        ut = "abc"
        tt = ut.taint()
        t_full = ut._cleanfor(MeritFull)
        t_part = ut._cleanfor(MeritPart)
        t_none = ut._cleanfor(MeritNone)
        t_all = ut._cleanfor(MeritFull)._cleanfor(MeritPart)\
                  ._cleanfor(MeritNone)

        self.assertTaintedAll(re.findall(tt, tt[0]))
        self.assertTaintedAll(re.findall(tt, ut[0]))
        self.assertTaintedAll(re.findall(ut, tt[0]))
        # the order of this tests matter, since we want to
        # make sure we did not break caching
        self.assertCleanAll(re.findall(ut, ut[0]))

        self.assertMeritsAll(re.findall(ut, tt[0]), [])
        self.assertMeritsAll(re.findall(ut, t_all[0]), [MeritFull])
        self.assertMeritsAll(re.findall(ut, t_full[0]), [MeritFull])
        self.assertMeritsAll(re.findall(ut, t_part[0]), [])
        self.assertMeritsAll(re.findall(ut, t_none[0]), [])

        self.assertMeritsAll(re.findall(tt, ut[0]), [])
        self.assertMeritsAll(re.findall(t_all, ut[0]), [MeritFull])
        self.assertMeritsAll(re.findall(t_full, ut[0]), [MeritFull])
        self.assertMeritsAll(re.findall(t_part, ut[0]), [])
        self.assertMeritsAll(re.findall(t_none, ut[0]), [])

        self.assertMeritsAll(re.findall(t_all, tt[0]), [])
        self.assertMeritsAll(re.findall(t_all, t_full[0]), [MeritFull])
        self.assertMeritsAll(re.findall(t_all, t_part[0]), [MeritPart])
        self.assertMeritsAll(re.findall(t_all, t_none[0]), [])

        self.assertMeritsAll(re.findall(tt, t_all[0]), [])
        self.assertMeritsAll(re.findall(t_full, t_all[0]), [MeritFull])
        self.assertMeritsAll(re.findall(t_part, t_all[0]), [MeritPart])
        self.assertMeritsAll(re.findall(t_none, t_all[0]), [])

    def test_finditer(self):
        ut = "abc"
        tt = ut.taint()
        t_full = ut._cleanfor(MeritFull)
        t_part = ut._cleanfor(MeritPart)
        t_none = ut._cleanfor(MeritNone)
        t_all = ut._cleanfor(MeritFull)._cleanfor(MeritPart)\
                  ._cleanfor(MeritNone)

        self.assertTaintedAll(re.finditer(tt, tt[0]))
        self.assertTaintedAll(re.finditer(tt, ut[0]))
        self.assertTaintedAll(re.finditer(ut, tt[0]))
        # the order of this tests matter, since we want to
        # make sure we did not break caching
        self.assertCleanAll(re.finditer(ut, ut[0]))

        self.assertMeritsAll(re.finditer(ut, tt[0]), [])
        self.assertMeritsAll(re.finditer(ut, t_all[0]), [MeritFull])
        self.assertMeritsAll(re.finditer(ut, t_full[0]), [MeritFull])
        self.assertMeritsAll(re.finditer(ut, t_part[0]), [])
        self.assertMeritsAll(re.finditer(ut, t_none[0]), [])

        self.assertMeritsAll(re.finditer(tt, ut[0]), [])
        self.assertMeritsAll(re.finditer(t_all, ut[0]), [MeritFull])
        self.assertMeritsAll(re.finditer(t_full, ut[0]), [MeritFull])
        self.assertMeritsAll(re.finditer(t_part, ut[0]), [])
        self.assertMeritsAll(re.finditer(t_none, ut[0]), [])

        self.assertMeritsAll(re.finditer(t_all, tt[0]), [])
        self.assertMeritsAll(re.finditer(t_all, t_full[0]), [MeritFull])
        self.assertMeritsAll(re.finditer(t_all, t_part[0]), [MeritPart])
        self.assertMeritsAll(re.finditer(t_all, t_none[0]), [])

        self.assertMeritsAll(re.finditer(tt, t_all[0]), [])
        self.assertMeritsAll(re.finditer(t_full, t_all[0]), [MeritFull])
        self.assertMeritsAll(re.finditer(t_part, t_all[0]), [MeritPart])
        self.assertMeritsAll(re.finditer(t_none, t_all[0]), [])

    def test_escape(self):
        ut = "[a-z]+"
        tt = ut.taint()
        t_full = ut._cleanfor(MeritFull)
        t_part = ut._cleanfor(MeritPart)
        t_none = ut._cleanfor(MeritNone)
        t_all = ut._cleanfor(MeritFull)._cleanfor(MeritPart)\
                  ._cleanfor(MeritNone)

        self.assertMerits(re.escape(tt), [])
        self.assertMerits(re.escape(t_full), [MeritFull])
        self.assertMerits(re.escape(t_part), [MeritPart])
        self.assertMerits(re.escape(t_none), [MeritNone])
        self.assertMerits(re.escape(t_all), [MeritFull, MeritPart, MeritNone])
        self.assertMerits(re.escape(ut), None)

    def test_compile(self):
        pattern = r"[a-z]+"
        text = "asdf"
        text_p = "asdf"._cleanfor(MeritPart)
        ur = re.compile(pattern)
        tr = re.compile(pattern.taint())
        r_full = re.compile(pattern._cleanfor(MeritFull))
        r_part = re.compile(pattern._cleanfor(MeritPart))
        r_none = re.compile(pattern._cleanfor(MeritNone))
        r_all = re.compile(pattern._cleanfor(MeritFull)._cleanfor(MeritPart)\
                  ._cleanfor(MeritNone))

        # search
        self.assertMerits(ur.search(text).group(0), None)
        self.assertMerits(tr.search(text).group(0), [])
        self.assertMerits(r_full.search(text).group(0), [MeritFull])
        self.assertMerits(r_part.search(text).group(0), [])
        self.assertMerits(r_none.search(text).group(0), [])
        self.assertMerits(r_all.search(text).group(0), [MeritFull])

        self.assertMerits(ur.search(text_p).group(0), [])
        self.assertMerits(tr.search(text_p).group(0), [])
        self.assertMerits(r_full.search(text_p).group(0), [])
        self.assertMerits(r_part.search(text_p).group(0), [])
        self.assertMerits(r_none.search(text_p).group(0), [])
        self.assertMerits(r_all.search(text_p).group(0), [])

        # match
        self.assertMerits(ur.match(text).group(0), None)
        self.assertMerits(tr.match(text).group(0), [])
        self.assertMerits(r_full.match(text).group(0), [MeritFull])
        self.assertMerits(r_part.match(text).group(0), [])
        self.assertMerits(r_none.match(text).group(0), [])
        self.assertMerits(r_all.match(text).group(0), [MeritFull])

        self.assertMerits(ur.match(text_p).group(0), [])
        self.assertMerits(tr.match(text_p).group(0), [])
        self.assertMerits(r_full.match(text_p).group(0), [])
        self.assertMerits(r_part.match(text_p).group(0), [])
        self.assertMerits(r_none.match(text_p).group(0), [])
        self.assertMerits(r_all.match(text_p).group(0), [])

        # split
        self.assertMeritsAll(ur.split(text), None)
        self.assertMeritsAll(tr.split(text), [])
        self.assertMeritsAll(r_full.split(text), [MeritFull])
        self.assertMeritsAll(r_part.split(text), [])
        self.assertMeritsAll(r_none.split(text), [])
        self.assertMeritsAll(r_all.split(text), [MeritFull])

        self.assertMeritsAll(ur.split(text_p), [])
        self.assertMeritsAll(tr.split(text_p), [])
        self.assertMeritsAll(r_full.split(text_p), [])
        self.assertMeritsAll(r_part.split(text_p), [MeritPart])
        self.assertMeritsAll(r_none.split(text_p), [])
        self.assertMeritsAll(r_all.split(text_p), [MeritPart])

        # sub
        self.assertMerits(ur.sub(text, text), None)
        self.assertMerits(tr.sub(text, text), [])
        self.assertMerits(r_full.sub(text, text), [MeritFull])
        self.assertMerits(r_part.sub(text, text), [])
        self.assertMerits(r_none.sub(text, text), [])
        self.assertMerits(r_all.sub(text, text), [MeritFull])

        self.assertMerits(ur.sub(text_p, text), [])
        self.assertMerits(tr.sub(text_p, text), [])
        self.assertMerits(r_full.sub(text_p, text), [])
        self.assertMerits(r_part.sub(text_p, text), [])
        self.assertMerits(r_none.sub(text_p, text), [])
        self.assertMerits(r_all.sub(text_p, text), [])

        self.assertMerits(ur.sub(text, text_p), [])
        self.assertMerits(tr.sub(text, text_p), [])
        self.assertMerits(r_full.sub(text, text_p), [])
        self.assertMerits(r_part.sub(text, text_p), [])
        self.assertMerits(r_none.sub(text, text_p), [])
        self.assertMerits(r_all.sub(text, text_p), [])

        self.assertMerits(ur.sub(text_p, text_p), [])
        self.assertMerits(tr.sub(text_p, text_p), [])
        self.assertMerits(r_full.sub(text_p, text_p), [])
        self.assertMerits(r_part.sub(text_p, text_p), [MeritPart])
        self.assertMerits(r_none.sub(text_p, text_p), [])
        self.assertMerits(r_all.sub(text_p, text_p), [MeritPart])

        # subn
        self.assertMerits(ur.subn(text, text)[0], None)
        self.assertMerits(tr.subn(text, text)[0], [])
        self.assertMerits(r_full.subn(text, text)[0], [MeritFull])
        self.assertMerits(r_part.subn(text, text)[0], [])
        self.assertMerits(r_none.subn(text, text)[0], [])
        self.assertMerits(r_all.subn(text, text)[0], [MeritFull])

        self.assertMerits(ur.subn(text_p, text)[0], [])
        self.assertMerits(tr.subn(text_p, text)[0], [])
        self.assertMerits(r_full.subn(text_p, text)[0], [])
        self.assertMerits(r_part.subn(text_p, text)[0], [])
        self.assertMerits(r_none.subn(text_p, text)[0], [])
        self.assertMerits(r_all.subn(text_p, text)[0], [])

        self.assertMerits(ur.subn(text, text_p)[0], [])
        self.assertMerits(tr.subn(text, text_p)[0], [])
        self.assertMerits(r_full.subn(text, text_p)[0], [])
        self.assertMerits(r_part.subn(text, text_p)[0], [])
        self.assertMerits(r_none.subn(text, text_p)[0], [])
        self.assertMerits(r_all.subn(text, text_p)[0], [])

        self.assertMerits(ur.subn(text_p, text_p)[0], [])
        self.assertMerits(tr.subn(text_p, text_p)[0], [])
        self.assertMerits(r_full.subn(text_p, text_p)[0], [])
        self.assertMerits(r_part.subn(text_p, text_p)[0], [MeritPart])
        self.assertMerits(r_none.subn(text_p, text_p)[0], [])
        self.assertMerits(r_all.subn(text_p, text_p)[0], [MeritPart])

        # findall
        self.assertMeritsAll(ur.findall(text), None)
        self.assertMeritsAll(tr.findall(text), [])
        self.assertMeritsAll(r_full.findall(text), [MeritFull])
        self.assertMeritsAll(r_part.findall(text), [])
        self.assertMeritsAll(r_none.findall(text), [])
        self.assertMeritsAll(r_all.findall(text), [MeritFull])

        self.assertMeritsAll(ur.findall(text_p), [])
        self.assertMeritsAll(tr.findall(text_p), [])
        self.assertMeritsAll(r_full.findall(text_p), [])
        self.assertMeritsAll(r_part.findall(text_p), [MeritPart])
        self.assertMeritsAll(r_none.findall(text_p), [])
        self.assertMeritsAll(r_all.findall(text_p), [MeritPart])

        # finditer
        self.assertMeritsAllGroups(ur.finditer(text), None)
        self.assertMeritsAllGroups(tr.finditer(text), [])
        self.assertMeritsAllGroups(r_full.finditer(text), [MeritFull])
        self.assertMeritsAllGroups(r_part.finditer(text), [])
        self.assertMeritsAllGroups(r_none.finditer(text), [])
        self.assertMeritsAllGroups(r_all.finditer(text), [MeritFull])

        self.assertMeritsAllGroups(ur.finditer(text_p), [])
        self.assertMeritsAllGroups(tr.finditer(text_p), [])
        self.assertMeritsAllGroups(r_full.finditer(text_p), [])
        self.assertMeritsAllGroups(r_part.finditer(text_p), [MeritPart])
        self.assertMeritsAllGroups(r_none.finditer(text_p), [])
        self.assertMeritsAllGroups(r_all.finditer(text_p), [MeritPart])

# functions for testing taint module - they should not live inside a class
# because mechanism for patching class methods is a bit different than for
# functions

def toplevel_source():
    return "abc"

def toplevel_cleaner(s):
    return s

def toplevel_sink(s):
    pass

def toplevel_propagator(s):
    return "abc"

def test_main():
    taint.enable(CONFIG_1)
    test_support.run_unittest(DecoratorTest, SimplePatcherTest,
                              ImportedObjectsPatchingTest, ConfigValidation,
                              PropagationContextsTest, PropagatorTest,
                              OptionsTest)
