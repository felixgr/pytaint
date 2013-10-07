import unittest, string
import sys
from test import test_support, string_tests


class MeritFull(Merit):
    propagation = Merit.FullPropagation

class MeritFull2(Merit):
    propagation = Merit.FullPropagation

class MeritPartial(Merit):
    propagation = Merit.PartialPropagation

class MeritPartial2(Merit):
    propagation = Merit.PartialPropagation

class MeritNone(Merit): # defaults to NonePropagation
    pass

class MeritNone2(Merit):
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

class TaintTest(AbstractTaintTest):
    def test_taint(self):
        t = 't'.taint()
        self.assertTainted(t)

        tt = t.taint()
        self.assertTainted(tt)

        ttt = 'a longer string that will be tainted'.taint()
        self.assertTainted(ttt)

        u = 'u'
        self.assertClean(u)

        self.assertEqual('x', 'x'.taint())
        self.assertEqual('a loooooooooooooooooooonger string', \
                         'a loooooooooooooooooooonger string'.taint())

    def test_taint_exception(self):
        try:
            with self.assertRaises(TaintError):
                raise TaintError
        except NameError:
            self.fail("TaintError is not defined.")

    def test_interning(self):
        t = 'ttttt'.taint()
        it = intern('ttttt')
        jt = intern('ttttt')
        u1 = intern('uuuuu')
        u2 = intern('uuuuu')
        self.assertRaises(TypeError, intern, t)

        self.assertEqual(it, t)
        self.assertIsNot(it, t)
        self.assertEqual(it, jt)
        self.assertIs(it, jt)
        self.assertEqual(it, jt.taint())
        self.assertIsNot(it, jt.taint())

        u1.taint()
        # u1 is interned and tainting it will return a
        # non-interned copy
        self.assertClean(u1)
        self.assertClean(u2)


class MeritsTest(AbstractTaintTest):
    def test_propagate(self):
        t = 'ttttt'.taint()
        t_full = t._cleanfor(MeritFull)
        t_part = t._cleanfor(MeritPartial)
        t_none = t._cleanfor(MeritNone)
        t_all = t._cleanfor(MeritFull)._cleanfor(MeritPartial)\
                 ._cleanfor(MeritNone)

        s = 'sssss'
        s_full = t._cleanfor(MeritFull2)._cleanfor(MeritFull)
        s_part = t._cleanfor(MeritPartial2)._cleanfor(MeritPartial)
        s_none = t._cleanfor(MeritNone2)._cleanfor(MeritNone)
        s_all = t._cleanfor(MeritFull2)._cleanfor(MeritPartial2)\
                 ._cleanfor(MeritNone2)

        self.assertMerits(t._propagate(t_full), [MeritFull])
        self.assertMerits(t._propagate(t_part), [MeritPartial])
        self.assertMerits(t._propagate(t_none), [MeritNone])
        self.assertMerits(t._propagate(t_all),
                          [MeritFull, MeritPartial, MeritNone])
        self.assertMerits(t_part._propagate(s_full), [MeritFull, MeritFull2])
        self.assertMerits(t_full._propagate(s_part), [MeritPartial,
                                                      MeritPartial2])
        self.assertMerits(t_none._propagate(s_none), [MeritNone, MeritNone2])
        self.assertMerits(t_all._propagate(s_all),
                          [MeritFull2, MeritPartial2, MeritNone2])

    def test_listing_merits(self):
        t = 'ttttt'.taint()
        t_full = t._cleanfor(MeritFull)
        t_part = t._cleanfor(MeritPartial)
        t_none = t._cleanfor(MeritNone)
        t_all = t._cleanfor(MeritFull)._cleanfor(MeritPartial)\
                 ._cleanfor(MeritNone)

        t_full2 = t._cleanfor(MeritFull)._cleanfor(MeritFull)
        t_part2 = t._cleanfor(MeritPartial)._cleanfor(MeritPartial)
        t_none2 = t._cleanfor(MeritNone)._cleanfor(MeritNone)
        t_all2 = t._cleanfor(MeritFull)._cleanfor(MeritPartial)\
                  ._cleanfor(MeritNone)
        t_full3 = t._cleanfor(MeritFull2)._cleanfor(MeritFull)
        t_part3 = t._cleanfor(MeritPartial2)._cleanfor(MeritPartial)
        t_none3 = t._cleanfor(MeritNone2)._cleanfor(MeritNone)
        t_all3 = t._cleanfor(MeritFull2)._cleanfor(MeritPartial2)\
                  ._cleanfor(MeritNone2)

        s = 'abcdef'
        s_full = s._cleanfor(MeritFull)
        s_part = s._cleanfor(MeritNone)
        s_none = s._cleanfor(MeritNone)
        s_all = s._cleanfor(MeritFull)._cleanfor(MeritPartial)\
                 ._cleanfor(MeritNone)

        u = 'uuuuu'
        self.assertMerits(t, [])
        self.assertMerits(s, None)
        self.assertMerits(u, None)
        self.assertMerits(t_full, [MeritFull])
        self.assertMerits(t_part, [MeritPartial])
        self.assertMerits(t_none, [MeritNone])
        self.assertMerits(t_all, [MeritNone, MeritFull, MeritPartial])

        self.assertMerits(t_full2, [MeritFull])
        self.assertMerits(t_part2, [MeritPartial])
        self.assertMerits(t_none2, [MeritNone])
        self.assertMerits(t_all, [MeritNone, MeritFull, MeritPartial])

        self.assertMerits(t_full3, [MeritFull, MeritFull2])
        self.assertMerits(t_part3, [MeritPartial, MeritPartial2])
        self.assertMerits(t_none3, [MeritNone, MeritNone2])

    def test_full_propagation(self):
        # this tests propagation semantics, not the _propagate method
        t = 'ttttt'.taint()
        t_full = t._cleanfor(MeritFull)
        t_part = t._cleanfor(MeritPartial)
        t_none = t._cleanfor(MeritNone)
        t_all = t._cleanfor(MeritFull)._cleanfor(MeritPartial)\
                 ._cleanfor(MeritNone)

        t_full2 = t._cleanfor(MeritFull)._cleanfor(MeritFull)
        t_part2 = t._cleanfor(MeritPartial)._cleanfor(MeritPartial)
        t_none2 = t._cleanfor(MeritNone)._cleanfor(MeritNone)
        t_all2 = t._cleanfor(MeritFull)._cleanfor(MeritPartial)\
                  ._cleanfor(MeritNone)
        t_full3 = t._cleanfor(MeritFull2)._cleanfor(MeritFull)
        t_part3 = t._cleanfor(MeritPartial2)._cleanfor(MeritPartial)
        t_none3 = t._cleanfor(MeritNone2)._cleanfor(MeritNone)
        t_all3 = t._cleanfor(MeritFull2)._cleanfor(MeritPartial2)\
              ._cleanfor(MeritNone2)
        t_all4 = t_all2._cleanfor(MeritFull2)._cleanfor(MeritPartial2)\
                ._cleanfor(MeritNone2)

        s = 'abcdef'
        s_full = s._cleanfor(MeritFull)
        s_part = s._cleanfor(MeritNone)
        s_none = s._cleanfor(MeritNone)
        s_all = s._cleanfor(MeritFull)._cleanfor(MeritPartial)\
                 ._cleanfor(MeritNone)

        u = 'uuuuu'

        self.assertMerits(u + s, None)

        self.assertMerits(u + t_full, [MeritFull])
        self.assertMerits(u + s_full, [MeritFull])
        self.assertMerits(u + t_all, [MeritFull])
        self.assertMerits(u + t_full2, [MeritFull])
        self.assertMerits(u + t_all2, [MeritFull])
        self.assertMerits(u + t_full3, [MeritFull, MeritFull2])
        self.assertMerits(u + t_all3, [MeritFull2])
        self.assertMerits(u + t_all4, [MeritFull2, MeritFull])

        self.assertMerits(s + t_full, [MeritFull])
        self.assertMerits(s + s_full, [MeritFull])
        self.assertMerits(s + t_all, [MeritFull])
        self.assertMerits(s + t_full2, [MeritFull])
        self.assertMerits(s + t_all2, [MeritFull])
        self.assertMerits(s + t_full3, [MeritFull, MeritFull2])
        self.assertMerits(s + t_all3, [MeritFull2])
        self.assertMerits(s + t_all4, [MeritFull2, MeritFull])

        self.assertMerits(t_full + t_full2, [MeritFull])
        self.assertMerits(t_full + t_full3, [MeritFull])
        self.assertMerits(t_full + t_all, [MeritFull])
        self.assertMerits(t_full + t_all2, [MeritFull])
        self.assertMerits(t_full + t_all3, [])

        self.assertMerits(t_full3 + t_full2, [MeritFull])
        self.assertMerits(t_full3 + t_all3, [MeritFull2])
        self.assertMerits(t_full3 + t_all4, [MeritFull2, MeritFull])
        self.assertMerits(t_full3 + t_all, [MeritFull])

        self.assertMerits(t_all + t_all2, [MeritFull, MeritPartial])
        self.assertMerits(t_all + t_all3, [])
        self.assertMerits(t_all2 + t_all3, [])
        self.assertMerits(t_all4 + t_all3, [MeritFull2, MeritPartial2])
        self.assertMerits(t_all4 + t_all, [MeritFull, MeritPartial])
        self.assertMerits(t_all4 + t_all2, [MeritFull, MeritPartial])

    def test_partial_propagation(self):
        # this tests propagation semantics, not the _propagate method
        t = 'ttttt'.taint()
        t_full = t._cleanfor(MeritFull)
        t_part = t._cleanfor(MeritPartial)
        t_none = t._cleanfor(MeritNone)
        t_all = t._cleanfor(MeritFull)._cleanfor(MeritPartial)\
                 ._cleanfor(MeritNone)

        t_full2 = t._cleanfor(MeritFull)._cleanfor(MeritFull)
        t_part2 = t._cleanfor(MeritPartial)._cleanfor(MeritPartial)
        t_none2 = t._cleanfor(MeritNone)._cleanfor(MeritNone)
        t_all2 = t._cleanfor(MeritFull)._cleanfor(MeritPartial)\
                  ._cleanfor(MeritNone)
        t_full3 = t._cleanfor(MeritFull2)._cleanfor(MeritFull)
        t_part3 = t._cleanfor(MeritPartial2)._cleanfor(MeritPartial)
        t_none3 = t._cleanfor(MeritNone2)._cleanfor(MeritNone)
        t_all3 = t._cleanfor(MeritFull2)._cleanfor(MeritPartial2)\
                  ._cleanfor(MeritNone2)
        t_all4 = t_all2._cleanfor(MeritFull2)._cleanfor(MeritPartial2)\
                       ._cleanfor(MeritNone2)

        s = 'abcdef'
        s_full = s._cleanfor(MeritFull)
        s_part = s._cleanfor(MeritNone)
        s_none = s._cleanfor(MeritNone)
        s_all = s._cleanfor(MeritFull)._cleanfor(MeritPartial)\
                 ._cleanfor(MeritNone)

        u = 'uuuuu'

        self.assertMerits(u + s, None)

        self.assertMerits(u + t_part, [])
        self.assertMerits(u + s_part, [])
        self.assertMerits(u + t_part2, [])
        self.assertMerits(u + t_part3, [])
        self.assertMerits(u + t_all, [MeritFull])
        self.assertMerits(u + t_all2, [MeritFull])
        self.assertMerits(u + t_all3, [MeritFull2])
        self.assertMerits(u + t_all4, [MeritFull2, MeritFull])

        self.assertMerits(s + t_part, [])
        self.assertMerits(s + s_part, [])
        self.assertMerits(s + t_part2, [])
        self.assertMerits(s + t_part3, [])
        self.assertMerits(s + t_all, [MeritFull])
        self.assertMerits(s + t_all2, [MeritFull])
        self.assertMerits(s + t_all3, [MeritFull2])
        self.assertMerits(s + t_all4, [MeritFull2, MeritFull])

        self.assertMerits(t_part + t_part2, [MeritPartial])
        self.assertMerits(t_part + t_part3, [MeritPartial])
        self.assertMerits(t_part + t_all, [MeritPartial])
        self.assertMerits(t_part + t_all2, [MeritPartial])
        self.assertMerits(t_part + t_all3, [])

        self.assertMerits(t_part3 + t_part2, [MeritPartial])
        self.assertMerits(t_part3 + t_all3, [MeritPartial2])
        self.assertMerits(t_part3 + t_all4, [MeritPartial2, MeritPartial])
        self.assertMerits(t_part3 + t_all, [MeritPartial])

        self.assertMerits(t_all + t_all2, [MeritFull, MeritPartial])
        self.assertMerits(t_all + t_all3, [])
        self.assertMerits(t_all2 + t_all3, [])
        self.assertMerits(t_all4 + t_all3, [MeritFull2, MeritPartial2])
        self.assertMerits(t_all4 + t_all, [MeritFull, MeritPartial])
        self.assertMerits(t_all4 + t_all2, [MeritFull, MeritPartial])

    def test_none_propagation(self):
        # this tests propagation semantics, not the _propagate method
        t = 'ttttt'.taint()
        t_full = t._cleanfor(MeritFull)
        t_part = t._cleanfor(MeritPartial)
        t_none = t._cleanfor(MeritNone)
        t_all = t._cleanfor(MeritFull)._cleanfor(MeritPartial)\
                 ._cleanfor(MeritNone)

        t_full2 = t._cleanfor(MeritFull)._cleanfor(MeritFull)
        t_part2 = t._cleanfor(MeritPartial)._cleanfor(MeritPartial)
        t_none2 = t._cleanfor(MeritNone)._cleanfor(MeritNone)
        t_all2 = t._cleanfor(MeritFull)._cleanfor(MeritPartial)\
                  ._cleanfor(MeritNone)
        t_full3 = t._cleanfor(MeritFull2)._cleanfor(MeritFull)
        t_part3 = t._cleanfor(MeritPartial2)._cleanfor(MeritPartial)
        t_none3 = t._cleanfor(MeritNone2)._cleanfor(MeritNone)
        t_all3 = t._cleanfor(MeritFull2)._cleanfor(MeritPartial2)\
                  ._cleanfor(MeritNone2)
        t_all4 = t_all2._cleanfor(MeritFull2)._cleanfor(MeritPartial2)\
                       ._cleanfor(MeritNone2)

        s = 'abcdef'
        s_full = s._cleanfor(MeritFull)
        s_part = s._cleanfor(MeritNone)
        s_none = s._cleanfor(MeritNone)
        s_all = s._cleanfor(MeritFull)._cleanfor(MeritPartial)\
                 ._cleanfor(MeritNone)

        u = 'uuuuu'

        words = [t, t_full, t_part, t_none, t_all, t_full2, t_part2, t_none2,
                 t_all2, t_full3, t_part3, t_none3, t_all3, t_all4, s, s_full,
                 s_part, s_none, s_all, u]

        for w in words:
            for v in words:
                m = (v + w)._merits()
                if m == None:
                    self.assertClean(w)
                    self.assertClean(v)
                    continue
                self.assertNotIn(MeritNone, m)
                self.assertNotIn(MeritNone2, m)

class UnaryStringOperationTest(AbstractTaintTest):
    """ Test string methods which use only one string argument - ie. where
    taint is just copied from the argument to result. """

    def test_repeat(self):
        self.assertTainted('abcd'.taint() * 0)
        self.assertTainted(''.taint() * 100)
        self.assertTainted('ABCD asdf'.taint() * 15)
        self.assertTainted('i am very long'.taint() * 10000)

        self.assertTainted('abcd'._cleanfor(MeritFull) * 0)
        self.assertTainted(''._cleanfor(MeritFull) * 100)
        self.assertTainted('ABCD asdf'._cleanfor(MeritFull) * 15)
        self.assertTainted('i am very long'._cleanfor(MeritFull) * 10000)

        self.assertTainted('abcd'._cleanfor(MeritPartial) * 0)
        self.assertTainted(''._cleanfor(MeritPartial) * 100)
        self.assertTainted('ABCD asdf'._cleanfor(MeritPartial) * 15)
        self.assertTainted('i am very long'._cleanfor(MeritPartial) * 10000)

        self.assertTainted('abcd'._cleanfor(MeritNone) * 0)
        self.assertTainted(''._cleanfor(MeritNone) * 100)
        self.assertTainted('ABCD asdf'._cleanfor(MeritNone) * 15)
        self.assertTainted('i am very long'._cleanfor(MeritNone) * 10000)

        self.assertClean('abcd' * 0)
        self.assertClean('' * 100)
        self.assertClean('ABCD' * 5)
        self.assertClean('a very long string' * 10000)

    def test_item(self):
        u = 'aaaa'
        t = 'aaaa'.taint()
        c = 'aaaa'._cleanfor(MeritFull)
        self.assertClean(u[1])
        self.assertClean(u[2])
        self.assertClean(u[1])
        self.assertClean(u[0])

        self.assertTainted(t[0])
        self.assertTainted(t[-1])
        self.assertTainted(t[2])
        self.assertTainted(t[-1])

        self.assertTainted(c[0])
        self.assertTainted(c[-2])
        self.assertTainted(c[1])
        self.assertTainted(c[2])

    def test_slice(self):
        u = 'aaaaaaaaa'
        t = 'ttttttttt'.taint()
        c = 'ccccccccc'._cleanfor(MeritFull)

        self.assertClean(u[1:])
        self.assertClean(u[-1:])
        self.assertClean(u[2:5])
        self.assertClean(u[2:])
        self.assertClean(u[:-2])
        self.assertClean(u[1:5])
        self.assertTainted(t[2:])
        self.assertTainted(t[-1:])
        self.assertTainted(t[3:10])
        self.assertTainted(t[2:6])
        self.assertTainted(t[:6])
        self.assertTainted(t[:0])

        self.assertTainted(c[1:])
        self.assertTainted(c[-1:])
        self.assertTainted(c[:0])
        self.assertTainted(c[-1:])
        self.assertTainted(c[4:3])

    def test_subscript(self):
        u = 'aaaaaaaaa'
        t = 'ttttttttt'.taint()
        c = 'ccccccccc'._cleanfor(MeritFull)

        self.assertClean(u[1::1])
        self.assertClean(u[-1::1])
        self.assertClean(u[2:5:1])
        self.assertClean(u[1:9:2])
        self.assertClean(u[8:1:-3])
        self.assertClean(u[::-1])
        self.assertClean(u[::-2])
        self.assertClean(u[2::1])
        self.assertClean(u[:-2:1])
        self.assertClean(u[1:5:1])
        self.assertClean(u[1:7:2])
        self.assertClean(u[-1::-2])
        self.assertClean(u[-1::2])
        self.assertTainted(t[2::1])
        self.assertTainted(t[-1::1])
        self.assertTainted(t[3:10:1])
        self.assertTainted(t[3:10:3])
        self.assertTainted(t[9:1:-1])
        self.assertTainted(t[2:6:1])
        self.assertTainted(t[:6:1])
        self.assertTainted(t[::3])
        self.assertTainted(t[::-1])
        self.assertTainted(t[-1::-1])
        self.assertTainted(t[:0:1])

        self.assertTainted(c[1::1])
        self.assertTainted(c[-1::1])
        self.assertTainted(c[:0:1])
        self.assertTainted(c[1:9:2])
        self.assertTainted(c[-1::1])
        self.assertTainted(c[-1:-7:-2])
        self.assertTainted(c[4:3:1])

    def test_lower(self):
        self.assertTainted('abcd'.taint().lower())
        self.assertTainted('aBCd 123'._cleanfor(MeritFull).lower())
        self.assertTainted('ABCD'.taint()._cleanfor(MeritNone).lower())
        self.assertTainted('ABCD XYZ'.taint().lower())
        self.assertTainted(''.taint().lower())
        self.assertTainted('1  3   \n\n'.taint().lower())

        self.assertClean('abcd'.lower())
        self.assertClean('aBCd 123'.lower())
        self.assertClean('ABCD'.lower())
        self.assertClean('ABCD XYZ'.lower())
        self.assertClean(''.lower())
        self.assertClean('1  3   \n\n'.lower())

    def test_upper(self):
        self.assertTainted('abcd'.taint().upper())
        self.assertTainted('aBCd 123'._cleanfor(MeritFull).upper())
        self.assertTainted('ABCD'.taint()._cleanfor(MeritNone).upper())
        self.assertTainted('ABCD XYZ'.taint().upper())
        self.assertTainted(''.taint().upper())
        self.assertTainted('1  3   \n\n'.taint().upper())

        self.assertClean('abcd'.upper())
        self.assertClean('aBCd 123'.upper())
        self.assertClean('ABCD'.upper())
        self.assertClean('ABCD XYZ'.upper())
        self.assertClean(''.upper())
        self.assertClean('1  3   \n\n'.upper())

    def test_title(self):
        self.assertTainted('abcd'.taint().title())
        self.assertTainted('aBCd 123'._cleanfor(MeritFull).title())
        self.assertTainted('ABCD'.taint()._cleanfor(MeritNone).title())
        self.assertTainted('ABCD XYZ'.taint().title())
        self.assertTainted(''.taint().title())
        self.assertTainted('1  3   \n\n'.taint().title())

        self.assertClean('abcd'.title())
        self.assertClean('aBCd 123'.title())
        self.assertClean('ABCD'.title())
        self.assertClean('ABCD XYZ'.title())
        self.assertClean(''.title())
        self.assertClean('1  3   \n\n'.title())

    def test_capitalize(self):
        self.assertTainted('abcd'.taint().title())
        self.assertTainted('aBCd qwer asafd'._cleanfor(MeritFull).title())
        self.assertTainted('ABCD'.taint()._cleanfor(MeritNone).title())
        self.assertTainted('ABCD XYZ'.taint().title())
        self.assertTainted(''.taint().title())
        self.assertTainted('asdf zxcv \n hjkl\n'.taint().title())

        self.assertClean('abcd'.title())
        self.assertClean('aBCd 123'.title())
        self.assertClean('ABCD'.title())
        self.assertClean('ABCD XYZ HJKL'.title())
        self.assertClean(''.title())
        self.assertClean('1  3   \n\n'.title())

    def test_zfill(self):
        self.assertTainted('12'.taint().zfill(10))
        self.assertTainted('+1234'.taint().zfill(10))
        self.assertTainted('-1234'.taint().zfill(2))
        self.assertTainted(''.taint().zfill(10))
        self.assertTainted('400400'.taint().zfill(3))
        self.assertTainted('123.432'.taint().zfill(10))

        self.assertTainted('23400000'._cleanfor(MeritNone).zfill(100))
        self.assertTainted('34434234'._cleanfor(MeritNone).zfill(3))
        self.assertTainted('-123234234'._cleanfor(MeritPartial).zfill(100))
        self.assertTainted('-999342'._cleanfor(MeritPartial).zfill(3))
        self.assertTainted('345555.4663'._cleanfor(MeritFull).zfill(100))
        self.assertTainted('3456765.466654'.\
                           _cleanfor(MeritFull).zfill(3))

        self.assertClean('234'.zfill(2))
        self.assertClean('-1453'.zfill(20))
        self.assertClean('1345.3345'.zfill(2))
        self.assertClean('6456.34354'.zfill(20))
        self.assertClean('-9999.5345'.zfill(2))
        self.assertClean('-1000.11234'.zfill(20))

        self.assertTainted(''.taint().zfill(1))
        self.assertClean('')

    def test_expandtabs(self):
        self.assertTainted(''.taint().expandtabs())
        self.assertTainted('\t'.taint().expandtabs())
        self.assertTainted('abcd \t qwer'.taint().expandtabs())
        self.assertTainted('\t\tABCD'.taint().expandtabs())
        self.assertTainted('ABCD\tXYZ'.taint().expandtabs())
        self.assertTainted('asdf\t123@:#$L zxcv \t\t hjkl\n'.\
                           taint().expandtabs())

        self.assertTainted(''._cleanfor(MeritFull).expandtabs())
        self.assertTainted('\t'._cleanfor(MeritFull).expandtabs())
        self.assertTainted('abcd \t qwer'._cleanfor(MeritNone).expandtabs())
        self.assertTainted('\t\tABCD'._cleanfor(MeritNone).expandtabs())
        self.assertTainted('ABCD\tXYZ'._cleanfor(MeritPartial).expandtabs())
        self.assertTainted('asdf\t123@:#$L zxcv \t\t hjkl\n'.\
                           _cleanfor(MeritPartial).expandtabs())

        self.assertClean(''.expandtabs())
        self.assertClean('\t'.expandtabs())
        self.assertClean('abcd \t qwer'.expandtabs())
        self.assertClean('\t\tABCD'.expandtabs())
        self.assertClean('ABCD\tXYZ'.expandtabs())
        self.assertClean('asdf\t123@:#$L zxcv \t\t hjkl\n'.expandtabs())

    def test_swapcase(self):
        self.assertTainted('abcd'.taint().swapcase())
        self.assertTainted('aBCd 123'._cleanfor(MeritFull).swapcase())
        self.assertTainted('ABCD'.taint()._cleanfor(MeritNone).swapcase())
        self.assertTainted('ABcd xyZ'.taint().swapcase())
        self.assertTainted(''.taint().swapcase())
        self.assertTainted('1  3   \n\n'.taint().swapcase())

        self.assertClean('abcd'.swapcase())
        self.assertClean('aBCd 123'.swapcase())
        self.assertClean('aBCD'.swapcase())
        self.assertClean('Abcd Xyz'.swapcase())
        self.assertClean(''.swapcase())
        self.assertClean('1  3   \n\n'.swapcase())

    def test_coding(self):
        ab = '\x41\x42'
        aa = '\xaa\xaa'

        self.assertClean(ab.decode())
        self.assertTainted(ab.taint().decode())
        self.assertMerits(ab._cleanfor(MeritFull).decode(),
                          [MeritFull])
        self.assertMerits(ab._cleanfor(MeritPartial).decode(),
                          [MeritPartial])
        self.assertMerits(ab._cleanfor(MeritNone)._cleanfor(MeritFull).decode(),
                          [MeritFull, MeritNone])

        self.assertClean(aa.decode(errors='ignore'))
        self.assertClean(aa.decode(errors='replace'))
        self.assertTainted(aa.taint().decode(errors='ignore'))
        self.assertMerits(aa._cleanfor(MeritFull).decode(errors='replace'),
                          [MeritFull])
        self.assertMerits(aa._cleanfor(MeritPartial).decode(errors='ignore'),
                          [MeritPartial])
        self.assertMerits(aa._cleanfor(MeritNone)._cleanfor(MeritFull).\
                          decode(errors='replace'),
                          [MeritFull, MeritNone])

        self.assertClean(ab.encode())
        self.assertTainted(ab.taint().encode())
        self.assertMerits(ab._cleanfor(MeritFull).encode(),
                          [MeritFull])
        self.assertMerits(ab._cleanfor(MeritPartial).encode(),
                          [MeritPartial])
        self.assertMerits(ab._cleanfor(MeritNone)._cleanfor(MeritFull).encode(),
                          [MeritFull, MeritNone])





class VariadicStringOperationTest(AbstractTaintTest):
    """ Test string operations that take more than one argument and where
    the propagation semantics is applied. """
    def test_concatenation(self):
        a = 'aaa'.taint()
        b = 'bbb'.taint()
        u = 'ccc'
        c = a + b
        d = a + u
        e = u + a
        f = u + u
        self.assertTainted(c)
        self.assertTainted(d)
        self.assertTainted(e)
        self.assertClean(f)

    def test_join(self):
        t = 'ttttt'.taint()
        u = 'uuuuu'
        a = 'aaaaa'._cleanfor(MeritFull)
        b = 'bbbbb'._cleanfor(MeritNone)
        c = u._cleanfor(MeritFull)._cleanfor(MeritNone)

        self.assertTainted(t.join([]))
        self.assertTainted(a.join([]))
        self.assertTainted(b.join([]))
        self.assertTainted(c.join([]))
        self.assertClean(u.join([]))

        self.assertTainted(t.join(['a']))
        self.assertTainted(a.join(['a']))
        self.assertTainted(b.join(['a']))
        self.assertTainted(c.join(['a']))
        self.assertClean(u.join(['a']))

        self.assertTainted(t.join(['a', '']))
        self.assertTainted(a.join(['', 'a']))
        self.assertTainted(b.join(['a', '']))
        self.assertTainted(c.join(['', 'a', '']))
        self.assertClean(u.join(['a', '']))

        self.assertTainted(t.join(['']))
        self.assertTainted(a.join(['', '']))
        self.assertTainted(c.join(['', '', '']))
        self.assertClean(u.join(['', '', '', '', '']))
        self.assertTainted(u.join(['', ''.taint(), '', '', '', '']))
        self.assertTainted(u.join([''._cleanfor(MeritFull), '', '', '']))
        self.assertTainted(u.join(['', '', t]))

        self.assertTainted(t.join(['a', 'xx']))
        self.assertTainted(t.join(['aaaaaaaaaaaa']))
        self.assertTainted(a.join(['b', 'axxxk']))
        self.assertTainted(b.join(['a', 'aa', 'f', 'g', 'h', 'r']))
        self.assertTainted(c.join(['c', 'afff', 'dddd']))
        self.assertClean(u.join(['aaaa']))
        self.assertClean(u.join(['aa', 'bb', 'cc', 'd']))
        self.assertTainted(u.join(['aa'.taint(), 'bb', 'cc', 'd']))
        self.assertTainted(u.join(['aa', 'bb'._cleanfor(MeritFull),\
                                   'cc'._cleanfor(MeritNone), 'd']))

    def test_split(self):
        t = 't  t t tt   tt'.taint()
        u = 'u  uu   uuu   uuuu  u'
        a = 'a  aa aa a    a'._cleanfor(MeritFull)
        b = 'b bbb   bb b'._cleanfor(MeritNone)
        c = u._cleanfor(MeritFull)._cleanfor(MeritNone)\
              ._cleanfor(MeritPartial)
        ss = '  '

        [self.assertTainted(x) for x in t.split()]
        [self.assertTainted(x) for x in a.split()]
        [self.assertTainted(x) for x in b.split()]
        [self.assertTainted(x) for x in c.split()]
        [self.assertClean(x) for x in u.split()]

        [self.assertTainted(x) for x in t.split(' ')]
        [self.assertTainted(x) for x in a.split(' ')]
        [self.assertTainted(x) for x in b.split(' ')]
        [self.assertTainted(x) for x in c.split(' ')]
        [self.assertClean(x) for x in u.split(' ')]

        [self.assertTainted(x) for x in t.split(' '.taint())]
        [self.assertTainted(x) for x in a.split(' '.taint())]
        [self.assertTainted(x) for x in b.split(' '.taint())]
        [self.assertTainted(x) for x in c.split(' '.taint())]
        [self.assertTainted(x) for x in u.split(' '.taint())]

        [self.assertTainted(x) for x in t.split(ss)]
        [self.assertTainted(x) for x in a.split(ss)]
        [self.assertTainted(x) for x in b.split(ss)]
        [self.assertTainted(x) for x in c.split(ss)]
        [self.assertClean(x) for x in u.split(ss)]

        [self.assertMerits(x, [MeritPartial]) for x in \
                           c.rpartition(' '._cleanfor(MeritPartial))]

    def test_rsplit(self):
        t = 't  t t tt   tt'.taint()
        u = 'u  uu   uuu   uuuu  u'
        a = 'a  aa aa a    a'._cleanfor(MeritFull)
        b = 'b bbb   bb b'._cleanfor(MeritNone)
        c = u._cleanfor(MeritFull)._cleanfor(MeritNone).\
              _cleanfor(MeritPartial)
        ss = '  '

        [self.assertTainted(x) for x in t.rsplit()]
        [self.assertTainted(x) for x in a.rsplit()]
        [self.assertTainted(x) for x in b.rsplit()]
        [self.assertTainted(x) for x in c.rsplit()]
        [self.assertClean(x) for x in u.rsplit()]

        [self.assertTainted(x) for x in t.rsplit(' ')]
        [self.assertTainted(x) for x in a.rsplit(' ')]
        [self.assertTainted(x) for x in b.rsplit(' ')]
        [self.assertTainted(x) for x in c.rsplit(' ')]
        [self.assertClean(x) for x in u.rsplit(' ')]

        [self.assertTainted(x) for x in t.rsplit(' '.taint())]
        [self.assertTainted(x) for x in a.rsplit(' '.taint())]
        [self.assertTainted(x) for x in b.rsplit(' '.taint())]
        [self.assertTainted(x) for x in c.rsplit(' '.taint())]
        [self.assertTainted(x) for x in u.rsplit(' '.taint())]

        [self.assertTainted(x) for x in t.rsplit(ss)]
        [self.assertTainted(x) for x in a.rsplit(ss)]
        [self.assertTainted(x) for x in b.rsplit(ss)]
        [self.assertTainted(x) for x in c.rsplit(ss)]
        [self.assertClean(x) for x in u.rsplit(ss)]

        [self.assertMerits(x, [MeritPartial]) for x in \
                           c.rpartition(' '._cleanfor(MeritPartial))]

    def test_splitlines(self):
        t = 't \n t\n t tt \n\n\n  tt'.taint()
        u = '\nu  uu n\n\n \n  uuuu  u'
        a = '\n\na \n aa aa a  \n\n  a'._cleanfor(MeritFull)
        b = 'b bbb\n   bb \n\nb'._cleanfor(MeritNone)
        c = u._cleanfor(MeritFull)._cleanfor(MeritNone).\
              _cleanfor(MeritPartial)

        [self.assertTainted(x) for x in t.splitlines()]
        [self.assertTainted(x) for x in a.splitlines()]
        [self.assertTainted(x) for x in b.splitlines()]
        [self.assertTainted(x) for x in c.splitlines()]
        [self.assertClean(x) for x in u.splitlines()]

        [self.assertTainted(x) for x in t.splitlines()]
        [self.assertTainted(x) for x in a.splitlines()]
        [self.assertTainted(x) for x in b.splitlines()]
        [self.assertTainted(x) for x in c.splitlines()]
        [self.assertClean(x) for x in u.splitlines()]

        [self.assertTainted(x) for x in t.splitlines()]
        [self.assertTainted(x) for x in a.splitlines()]
        [self.assertTainted(x) for x in b.splitlines()]
        [self.assertTainted(x) for x in c.splitlines()]
        [self.assertClean(x) for x in u.splitlines()]

        [self.assertTainted(x) for x in t.splitlines()]
        [self.assertTainted(x) for x in a.splitlines()]
        [self.assertTainted(x) for x in b.splitlines()]
        [self.assertTainted(x) for x in c.splitlines()]
        [self.assertClean(x) for x in u.splitlines()]

    def test_rpartition(self):
        t = 't  t t tt   tt'.taint()
        u = 'u  uu   uuu   uuuu  u'
        a = 'a  aa aa a    a'._cleanfor(MeritFull)
        b = 'b bbb   bb b'._cleanfor(MeritNone)
        c = u._cleanfor(MeritFull)._cleanfor(MeritNone).\
              _cleanfor(MeritPartial)
        ss = '  '
        tt = '  '.taint()

        [self.assertTainted(x) for x in t.rpartition(' ')]
        [self.assertTainted(x) for x in a.rpartition(' ')]
        [self.assertTainted(x) for x in b.rpartition(' ')]
        [self.assertTainted(x) for x in c.rpartition(' ')]
        [self.assertClean(x) for x in u.rpartition(' ')]

        [self.assertTainted(x) for x in t.rpartition(' '.taint())]
        [self.assertTainted(x) for x in a.rpartition(' '.taint())]
        [self.assertTainted(x) for x in b.rpartition(' '.taint())]
        [self.assertTainted(x) for x in c.rpartition(' '.taint())]
        [self.assertTainted(x) for x in u.rpartition(' '.taint())]

        [self.assertTainted(x) for x in t.rpartition(ss)]
        [self.assertTainted(x) for x in a.rpartition(ss)]
        [self.assertTainted(x) for x in b.rpartition(ss)]
        [self.assertTainted(x) for x in c.rpartition(ss)]
        [self.assertClean(x) for x in u.rpartition(ss)]

        [self.assertTainted(x) for x in t.rpartition(tt)]
        [self.assertTainted(x) for x in a.rpartition(tt)]
        [self.assertTainted(x) for x in b.rpartition(tt)]
        [self.assertTainted(x) for x in c.rpartition(tt)]
        [self.assertTainted(x) for x in u.rpartition(tt)]

        [self.assertMerits(x, [MeritPartial]) for x in \
                           c.rpartition(' '._cleanfor(MeritPartial))]

    def test_partition(self):
        t = 't  t t tt   tt'.taint()
        u = 'u  uu   uuu   uuuu  u'
        a = 'a  aa aa a    a'._cleanfor(MeritFull)
        b = 'b bbb   bb b'._cleanfor(MeritNone)
        c = u._cleanfor(MeritFull)._cleanfor(MeritNone).\
              _cleanfor(MeritPartial)
        ss = '  '
        tt = '  '.taint()

        [self.assertTainted(x) for x in t.partition(' ')]
        [self.assertTainted(x) for x in a.partition(' ')]
        [self.assertTainted(x) for x in b.partition(' ')]
        [self.assertTainted(x) for x in c.partition(' ')]
        [self.assertClean(x) for x in u.partition(' ')]

        [self.assertTainted(x) for x in t.partition(' '.taint())]
        [self.assertTainted(x) for x in a.partition(' '.taint())]
        [self.assertTainted(x) for x in b.partition(' '.taint())]
        [self.assertTainted(x) for x in c.partition(' '.taint())]
        [self.assertTainted(x) for x in u.partition(' '.taint())]

        [self.assertTainted(x) for x in t.partition(ss)]
        [self.assertTainted(x) for x in a.partition(ss)]
        [self.assertTainted(x) for x in b.partition(ss)]
        [self.assertTainted(x) for x in c.partition(ss)]
        [self.assertClean(x) for x in u.partition(ss)]

        [self.assertTainted(x) for x in t.partition(tt)]
        [self.assertTainted(x) for x in a.partition(tt)]
        [self.assertTainted(x) for x in b.partition(tt)]
        [self.assertTainted(x) for x in c.partition(tt)]
        [self.assertTainted(x) for x in u.partition(tt)]

        [self.assertMerits(x, [MeritPartial]) for x in \
                           c.partition(' '._cleanfor(MeritPartial))]

    def test_strip(self):
        t = '   t  t t tt   tt'.taint()
        u = 'u  uu   uuu   uuuu  u'
        a = 'a  aa aa a    a'._cleanfor(MeritFull)
        b = 'b bbb   bb b'._cleanfor(MeritNone)
        c = u._cleanfor(MeritFull)._cleanfor(MeritNone)

        x = 'xy'
        y = 'xy'.taint()
        z = 'xy'._cleanfor(MeritPartial)

        self.assertTainted(t.strip())
        self.assertTainted(a.strip())
        self.assertTainted(b.strip())
        self.assertTainted(c.strip())
        self.assertClean(u.strip())

        self.assertTainted(t.strip(x))
        self.assertTainted(a.strip(x))
        self.assertTainted(b.strip(x))
        self.assertTainted(c.strip(x))
        self.assertClean(u.strip(x))

        self.assertTainted(t.strip(y))
        self.assertTainted(a.strip(y))
        self.assertTainted(b.strip(y))
        self.assertTainted(c.strip(y))
        self.assertTainted(u.strip(y))

        self.assertTainted(t.strip(z))
        self.assertTainted(a.strip(z))
        self.assertTainted(b.strip(z))
        self.assertTainted(c.strip(z))
        self.assertTainted(u.strip(z))

    def test_rstrip(self):
        t = '   t  t t tt   tt'.taint()
        u = 'u  uu   uuu   uuuu  u'
        a = 'a  aa aa a    a'._cleanfor(MeritFull)
        b = 'b bbb   bb b'._cleanfor(MeritNone)
        c = u._cleanfor(MeritFull)._cleanfor(MeritNone)

        x = 'xy'
        y = 'xy'.taint()
        z = 'xy'._cleanfor(MeritPartial)

        self.assertTainted(t.strip())
        self.assertTainted(a.strip())
        self.assertTainted(b.strip())
        self.assertTainted(c.strip())
        self.assertClean(u.strip())

        self.assertTainted(t.strip(x))
        self.assertTainted(a.strip(x))
        self.assertTainted(b.strip(x))
        self.assertTainted(c.strip(x))
        self.assertClean(u.strip(x))

        self.assertTainted(t.strip(y))
        self.assertTainted(a.strip(y))
        self.assertTainted(b.strip(y))
        self.assertTainted(c.strip(y))
        self.assertTainted(u.strip(y))

        self.assertTainted(t.strip(z))
        self.assertTainted(a.strip(z))
        self.assertTainted(b.strip(z))
        self.assertTainted(c.strip(z))
        self.assertTainted(u.strip(z))

    def test_lstrip(self):
        t = '   t  t t tt   tt'.taint()
        u = 'u  uu   uuu   uuuu  u'
        a = 'a  aa aa a    a'._cleanfor(MeritFull)
        b = 'b bbb   bb b'._cleanfor(MeritNone)
        c = u._cleanfor(MeritFull)._cleanfor(MeritNone)

        x = 'xy'
        y = 'xy'.taint()
        z = 'xy'._cleanfor(MeritPartial)

        self.assertTainted(t.strip())
        self.assertTainted(a.strip())
        self.assertTainted(b.strip())
        self.assertTainted(c.strip())
        self.assertClean(u.strip())

        self.assertTainted(t.strip(x))
        self.assertTainted(a.strip(x))
        self.assertTainted(b.strip(x))
        self.assertTainted(c.strip(x))
        self.assertClean(u.strip(x))

        self.assertTainted(t.strip(y))
        self.assertTainted(a.strip(y))
        self.assertTainted(b.strip(y))
        self.assertTainted(c.strip(y))
        self.assertTainted(u.strip(y))

        self.assertTainted(t.strip(z))
        self.assertTainted(a.strip(z))
        self.assertTainted(b.strip(z))
        self.assertTainted(c.strip(z))
        self.assertTainted(u.strip(z))

    def test_ljust(self):
        t = '   t  t t tt   tt'.taint()
        t2 = ''.taint()
        u = 'u  uu   uuu   uuuu  u'
        u2 = ''
        a = 'a  aa aa a    a'._cleanfor(MeritFull)
        b = u._cleanfor(MeritFull)._cleanfor(MeritNone)

        x = '-'
        y = '-'.taint()
        z = '-'._cleanfor(MeritPartial)

        self.assertTainted(t.ljust(20))
        self.assertTainted(t2.ljust(20))
        self.assertTainted(a.ljust(20))
        self.assertTainted(b.ljust(20))
        self.assertClean(u.ljust(20))
        self.assertClean(u2.ljust(20))

        self.assertTainted(t.ljust(0, x))
        self.assertTainted(t2.ljust(0, x))
        self.assertTainted(a.ljust(0, x))
        self.assertTainted(b.ljust(0, x))
        self.assertClean(u.ljust(0, x))
        self.assertClean(u2.ljust(0, x))

        self.assertTainted(t.ljust(30, x))
        self.assertTainted(t2.ljust(30, x))
        self.assertTainted(a.ljust(30, x))
        self.assertTainted(b.ljust(30, x))
        self.assertClean(u.ljust(30, x))
        self.assertClean(u2.ljust(30, x))

        self.assertTainted(t.ljust(0, y))
        self.assertTainted(t2.ljust(0, y))
        self.assertTainted(a.ljust(0, y))
        self.assertTainted(b.ljust(0, y))
        self.assertTainted(u.ljust(0, y))
        self.assertTainted(u2.ljust(0, y))

        self.assertTainted(t.ljust(30, y))
        self.assertTainted(t2.ljust(30, y))
        self.assertTainted(a.ljust(30, y))
        self.assertTainted(b.ljust(30, y))
        self.assertTainted(u.ljust(30, y))
        self.assertTainted(u2.ljust(30, y))

        self.assertTainted(t.ljust(0, z))
        self.assertTainted(t2.ljust(0, z))
        self.assertTainted(a.ljust(0, z))
        self.assertTainted(b.ljust(0, z))
        self.assertTainted(u.ljust(0, z))
        self.assertTainted(u2.ljust(0, z))

        self.assertTainted(t.ljust(30, z))
        self.assertTainted(t2.ljust(30, z))
        self.assertTainted(a.ljust(30, z))
        self.assertTainted(b.ljust(30, z))
        self.assertTainted(u.ljust(30, z))
        self.assertTainted(u2.ljust(30, z))

        # check if interning is not broken
        self.assertTainted('u'.ljust(0, 'x'.taint()))
        self.assertClean('u')
        self.assertTainted('u'.taint().ljust(20, 'x'))
        self.assertClean('u')
        self.assertTainted('u'.ljust(0, 'x'.taint()))
        self.assertClean('u')
        self.assertTainted('u'.taint().ljust(20, 'x'))
        self.assertClean('u')

    def test_rjust(self):
        t = '   t  t t tt   tt'.taint()
        t2 = ''.taint()
        u = 'u  uu   uuu   uuuu  u'
        u2 = ''
        a = 'a  aa aa a    a'._cleanfor(MeritFull)
        b = u._cleanfor(MeritFull)._cleanfor(MeritNone)

        x = '-'
        y = '-'.taint()
        z = '-'._cleanfor(MeritPartial)

        self.assertTainted(t.rjust(20))
        self.assertTainted(t2.rjust(20))
        self.assertTainted(a.rjust(20))
        self.assertTainted(b.rjust(20))
        self.assertClean(u.rjust(20))
        self.assertClean(u2.rjust(20))

        self.assertTainted(t.rjust(0, x))
        self.assertTainted(t2.rjust(0, x))
        self.assertTainted(a.rjust(0, x))
        self.assertTainted(b.rjust(0, x))
        self.assertClean(u.rjust(0, x))
        self.assertClean(u2.rjust(0, x))

        self.assertTainted(t.rjust(30, x))
        self.assertTainted(t2.rjust(30, x))
        self.assertTainted(a.rjust(30, x))
        self.assertTainted(b.rjust(30, x))
        self.assertClean(u.rjust(30, x))
        self.assertClean(u2.rjust(30, x))

        self.assertTainted(t.rjust(0, y))
        self.assertTainted(t2.rjust(0, y))
        self.assertTainted(a.rjust(0, y))
        self.assertTainted(b.rjust(0, y))
        self.assertTainted(u.rjust(0, y))
        self.assertTainted(u2.rjust(0, y))

        self.assertTainted(t.rjust(30, y))
        self.assertTainted(t2.rjust(30, y))
        self.assertTainted(a.rjust(30, y))
        self.assertTainted(b.rjust(30, y))
        self.assertTainted(u.rjust(30, y))
        self.assertTainted(u2.rjust(30, y))

        self.assertTainted(t.rjust(0, z))
        self.assertTainted(t2.rjust(0, z))
        self.assertTainted(a.rjust(0, z))
        self.assertTainted(b.rjust(0, z))
        self.assertTainted(u.rjust(0, z))
        self.assertTainted(u2.rjust(0, z))

        self.assertTainted(t.rjust(30, z))
        self.assertTainted(t2.rjust(30, z))
        self.assertTainted(a.rjust(30, z))
        self.assertTainted(b.rjust(30, z))
        self.assertTainted(u.rjust(30, z))
        self.assertTainted(u2.rjust(30, z))

        # check if interning is not broken
        self.assertTainted('u'.rjust(0, 'x'.taint()))
        self.assertClean('u')
        self.assertTainted('u'.taint().rjust(20, 'x'))
        self.assertClean('u')
        self.assertTainted('u'.rjust(0, 'x'.taint()))
        self.assertClean('u')
        self.assertTainted('u'.taint().rjust(20, 'x'))
        self.assertClean('u')

    def test_center(self):
        t = '   t  t t tt   tt'.taint()
        t2 = ''.taint()
        u = 'u  uu   uuu   uuuu  u'
        u2 = ''
        a = 'a  aa aa a    a'._cleanfor(MeritFull)
        b = u._cleanfor(MeritFull)._cleanfor(MeritNone)

        x = '-'
        y = '-'.taint()
        z = '-'._cleanfor(MeritPartial)

        self.assertTainted(t.center(20))
        self.assertTainted(t2.center(20))
        self.assertTainted(a.center(20))
        self.assertTainted(b.center(20))
        self.assertClean(u.center(20))
        self.assertClean(u2.center(20))

        self.assertTainted(t.center(0, x))
        self.assertTainted(t2.center(0, x))
        self.assertTainted(a.center(0, x))
        self.assertTainted(b.center(0, x))
        self.assertClean(u.center(0, x))
        self.assertClean(u2.center(0, x))

        self.assertTainted(t.center(30, x))
        self.assertTainted(t2.center(30, x))
        self.assertTainted(a.center(30, x))
        self.assertTainted(b.center(30, x))
        self.assertClean(u.center(30, x))
        self.assertClean(u2.center(30, x))

        self.assertTainted(t.center(0, y))
        self.assertTainted(t2.center(0, y))
        self.assertTainted(a.center(0, y))
        self.assertTainted(b.center(0, y))
        self.assertTainted(u.center(0, y))
        self.assertTainted(u2.center(0, y))

        self.assertTainted(t.center(30, y))
        self.assertTainted(t2.center(30, y))
        self.assertTainted(a.center(30, y))
        self.assertTainted(b.center(30, y))
        self.assertTainted(u.center(30, y))
        self.assertTainted(u2.center(30, y))

        self.assertTainted(t.center(0, z))
        self.assertTainted(t2.center(0, z))
        self.assertTainted(a.center(0, z))
        self.assertTainted(b.center(0, z))
        self.assertTainted(u.center(0, z))
        self.assertTainted(u2.center(0, z))

        self.assertTainted(t.center(30, z))
        self.assertTainted(t2.center(30, z))
        self.assertTainted(a.center(30, z))
        self.assertTainted(b.center(30, z))
        self.assertTainted(u.center(30, z))
        self.assertTainted(u2.center(30, z))

        # check if interning is not broken
        self.assertTainted('u'.center(0, 'x'.taint()))
        self.assertClean('u')
        self.assertTainted('u'.taint().center(20, 'x'))
        self.assertClean('u')
        self.assertTainted('u'.center(0, 'x'.taint()))
        self.assertClean('u')
        self.assertTainted('u'.taint().center(20, 'x'))
        self.assertClean('u')

    def test_replace(self):
        s = 'abc def def def'
        a = 'def'
        b = 'xyz'
        st = s.taint()
        at = s.taint()
        bt = s.taint()

        self.assertClean(s.replace(a, b))
        self.assertTainted(st.replace(a, b))
        self.assertTainted(s.replace(at, b))
        self.assertTainted(st.replace(at, b))
        self.assertTainted(s.replace(a, bt))
        self.assertTainted(st.replace(a, bt))
        self.assertTainted(s.replace(at, bt))
        self.assertTainted(st.replace(at, bt))

    def test_format_operator(self):
        # test formatting using the % operator
        t = 'ttttt'.taint()
        t_full = t._cleanfor(MeritFull)
        t_part = t._cleanfor(MeritPartial)
        t_none = t._cleanfor(MeritNone)
        t_all = t._cleanfor(MeritFull)._cleanfor(MeritPartial)\
                 ._cleanfor(MeritNone)

        fmt = "%s %s %s %%"
        fmt_taint = fmt.taint()
        fmt_full = fmt_taint._cleanfor(MeritFull)
        fmt_part = fmt_taint._cleanfor(MeritPartial)
        fmt_none = fmt_taint._cleanfor(MeritNone)
        fmt_all = fmt_full._cleanfor(MeritPartial)._cleanfor(MeritNone)

        self.assertClean(fmt % ('a', 'b', 'c'))
        self.assertTainted(fmt_taint % ('a', 'b', 'c'))
        self.assertTainted(fmt_taint % (t, t, t))
        self.assertTainted(fmt % ('a', 'b', t))
        self.assertTainted(fmt % (t, 'b', t))
        self.assertTainted(fmt % ('a', t, 'b'))

        self.assertMerits(fmt % (t, 'a', t_full), [])
        self.assertMerits(fmt % ('b', 'a', t_full), [MeritFull])
        self.assertMerits(fmt % (t_all , t_full, 'a'), [MeritFull])
        self.assertMerits(fmt_taint % (t, 'a', t_full), [])
        self.assertMerits(fmt_taint % ('b', 'a', t_full), [])
        self.assertMerits(fmt_taint % (t_all , t_full, 'a'), [])

        self.assertMerits(fmt_full % (t_all , t_full, 'a'), [MeritFull])
        self.assertMerits(fmt_all % (t_all , t_full, 'a'), [MeritFull])
        self.assertMerits(fmt_part % (t_part , t_all, t_all), [MeritPartial])
        self.assertMerits(fmt_all % (t_all, t_part, t_all), [MeritPartial])
        self.assertMerits(fmt_none % (t_none , t_all, 'c'), [])
        self.assertMerits(fmt_all % (t_all, t_none, t_all), [])

    def test_format_method(self):
        # test formatting using the format method
        t = 'ttttt'.taint()
        t_full = t._cleanfor(MeritFull)
        t_part = t._cleanfor(MeritPartial)
        t_none = t._cleanfor(MeritNone)
        t_all = t._cleanfor(MeritFull)._cleanfor(MeritPartial)\
                 ._cleanfor(MeritNone)

        fmt = "{} {} {} {{}}"
        fmt_taint = fmt.taint()
        fmt_full = fmt_taint._cleanfor(MeritFull)
        fmt_part = fmt_taint._cleanfor(MeritPartial)
        fmt_none = fmt_taint._cleanfor(MeritNone)
        fmt_all = fmt_full._cleanfor(MeritPartial)._cleanfor(MeritNone)

        self.assertClean(fmt.format('a', 'b', 'c'))
        # TODO(marcinf) specification says that result of below operation
        # should be tainted. However, since the last argument ('d') is not
        # interpolated into format string, it is clean. Change the docs
        # accordingly to mention that taint is propagated only across the
        # relevant arguments.
        self.assertClean(fmt.format('a', 'b', 'c', 'd'.taint()))
        self.assertTainted(fmt_taint.format('a', 'b', 'c'))
        self.assertTainted(fmt_taint.format(t, t, t))
        self.assertTainted(fmt.format('a', 'b', t))
        self.assertTainted(fmt.format(t, 'b', t))
        self.assertTainted(fmt.format('a', t, 'b'))

        self.assertMerits(fmt.format(t, 'a', t_full), [])
        self.assertMerits(fmt.format('b', 'a', t_full), [MeritFull])
        self.assertMerits(fmt.format(t_all , t_full, 'a'), [MeritFull])
        self.assertMerits(fmt_taint.format(t, 'a', t_full), [])
        self.assertMerits(fmt_taint.format('b', 'a', t_full), [])
        self.assertMerits(fmt_taint.format(t_all , t_full, 'a'), [])

        self.assertMerits(fmt_full.format(t_all , t_full, 'a'), [MeritFull])
        self.assertMerits(fmt_all.format(t_all , t_full, 'a'), [MeritFull])
        self.assertMerits(fmt_part.format(t_part , t_all, t_all),
                          [MeritPartial])
        self.assertMerits(fmt_all.format(t_all, t_part, t_all),
                          [MeritPartial])
        self.assertMerits(fmt_none.format(t_none , t_all, 'c'), [])
        self.assertMerits(fmt_all.format(t_all, t_none, t_all), [])

        fmt = "{2} {0} {1} {{}}"
        fmt_taint = fmt.taint()
        fmt_full = fmt_taint._cleanfor(MeritFull)
        fmt_part = fmt_taint._cleanfor(MeritPartial)
        fmt_none = fmt_taint._cleanfor(MeritNone)
        fmt_all = fmt_full._cleanfor(MeritPartial)._cleanfor(MeritNone)

        self.assertClean(fmt.format('a', 'b', 'c'))
        self.assertClean(fmt.format('a', 'b', 'c', 'd'.taint()))
        self.assertTainted(fmt_taint.format('a', 'b', 'c'))
        self.assertTainted(fmt_taint.format(t, t, t))
        self.assertTainted(fmt.format('a', 'b', t))
        self.assertTainted(fmt.format(t, 'b', t))
        self.assertTainted(fmt.format('a', t, 'b'))

        self.assertMerits(fmt.format(t, 'a', t_full), [])
        self.assertMerits(fmt.format('b', 'a', t_full), [MeritFull])
        self.assertMerits(fmt.format(t_all , t_full, 'a'), [MeritFull])
        self.assertMerits(fmt_taint.format(t, 'a', t_full), [])
        self.assertMerits(fmt_taint.format('b', 'a', t_full), [])
        self.assertMerits(fmt_taint.format(t_all , t_full, 'a'), [])

        self.assertMerits(fmt_full.format(t_all , t_full, 'a'), [MeritFull])
        self.assertMerits(fmt_all.format(t_all , t_full, 'a'), [MeritFull])
        self.assertMerits(fmt_part.format(t_part , t_all, t_all),
                          [MeritPartial])
        self.assertMerits(fmt_all.format(t_all, t_part, t_all),
                          [MeritPartial])
        self.assertMerits(fmt_none.format(t_none , t_all, 'c'), [])
        self.assertMerits(fmt_all.format(t_all, t_none, t_all), [])

        fmt = "{x} {y[0]} {z.t} {{}}"
        fmt_taint = fmt.taint()
        fmt_full = fmt_taint._cleanfor(MeritFull)
        fmt_part = fmt_taint._cleanfor(MeritPartial)
        fmt_none = fmt_taint._cleanfor(MeritNone)
        fmt_all = fmt_full._cleanfor(MeritPartial)._cleanfor(MeritNone)

        def pack(x):
            """ Create a dummy object d satisfying d.t == x. This is for
            testing formatting string with objects' attributes. """
            return type('zt', (), {'t': x})

        self.assertClean(fmt.format(x='a', y=['b'], z=pack('c')))
        self.assertClean(fmt.format(x='a', y=['b'], z=pack('c'),
                                    t='d'.taint()))
        self.assertTainted(fmt_taint.format(x='a', y=['b'], z=pack('c')))
        self.assertTainted(fmt_taint.format(x=t, y=[t], z=pack(t)))
        self.assertTainted(fmt.format(x='a', y=['b'], z=pack(t)))
        self.assertTainted(fmt.format(x=t, y=['b'], z=pack(t)))
        self.assertTainted(fmt.format(x='a', y=[t], z=pack('b')))

        self.assertMerits(fmt.format(x=t, y=['a'], z=pack(t_full)),
                          [])
        self.assertMerits(fmt.format(x='b', y=['a'], z=pack(t_full)),
                          [MeritFull])
        self.assertMerits(fmt.format(x=t_all , y=[t_full], z=pack('a')),
                          [MeritFull])
        self.assertMerits(fmt_taint.format(x=t, y=['a'], z=pack(t_full)),
                          [])
        self.assertMerits(fmt_taint.format(x='b', y=['a'], z=pack(t_full)),
                          [])
        self.assertMerits(fmt_taint.format(x=t_all , y=[t_full], z=pack('a')),
                          [])

        self.assertMerits(fmt_full.format(x=t_all , y=[t_full], z=pack('a')),
                          [MeritFull])
        self.assertMerits(fmt_all.format(x=t_all , y=[t_full], z=pack('a')),
                          [MeritFull])
        self.assertMerits(fmt_part.format(x=t_part , y=[t_all], z=pack(t_all)),
                          [MeritPartial])
        self.assertMerits(fmt_all.format(x=t_all, y=[t_part], z=pack(t_all)),
                          [MeritPartial])
        self.assertMerits(fmt_none.format(x=t_none , y=[t_all], z=pack('c')),
                          [])
        self.assertMerits(fmt_all.format(x=t_all, y=[t_none], z=pack(t_all)),
                          [])

        nested = "{0:{a}}"
        self.assertMerits(nested.taint().format('t', a='s'), [])
        self.assertMerits(nested._cleanfor(MeritFull).format('t', a='s'),
                          [MeritFull])
        self.assertMerits(nested._cleanfor(MeritPartial).format('t', a='s'),
                          [])
        self.assertMerits(nested._cleanfor(MeritPartial).format(
                                    t_part, a='s'._cleanfor(MeritPartial)),
                          [MeritPartial])
        self.assertMerits(nested._cleanfor(MeritNone).format(
                                    t_none, a='s'._cleanfor(MeritNone)),
                          [])



    def test_translate(self):
        t = string.maketrans('ab', 'ba')
        d1 = 'bcd'
        d2 = 'ijk'
        s1 = 'abcdef'
        s2 = 'ghijkl'
        s0 = 'a'

        self.assertTainted(s1.taint().translate(t, d1))
        self.assertTainted(s2.taint().translate(t, d1))
        self.assertTainted(s1.translate(t.taint(), d2))
        self.assertTainted(s2.translate(t, d2.taint()))
        self.assertTainted(s1.taint().translate(t.taint()))
        self.assertTainted(s2.translate(t.taint()))

        self.assertTainted(s1.taint().translate(t, d1))
        self.assertTainted(s2.taint().translate(t, d1))
        self.assertTainted(s1.translate(t.taint(), d2))
        self.assertTainted(s2.translate(t, d2.taint()))
        self.assertTainted(s1.taint().translate(t.taint()))
        self.assertTainted(s2.translate(t.taint()))
        self.assertTainted(s0.translate(t.taint()))
        self.assertTainted(s0.taint().translate(t))
        self.assertTainted(s0.translate(t, d2.taint()))
        self.assertTainted(s0.taint().translate(t, d2))

        self.assertMerits(s1._cleanfor(MeritFull).translate(t, d1),
                          [MeritFull])
        self.assertMerits(s2._cleanfor(MeritFull).translate(t, d1),
                          [MeritFull])
        self.assertMerits(s1._cleanfor(MeritPartial).translate(t, d1),
                          [])
        self.assertMerits(s2._cleanfor(MeritPartial).translate(t, d1),
                          [])
        self.assertMerits(s1._cleanfor(MeritPartial)
                          .translate(t._cleanfor(MeritPartial),
                                     d1._cleanfor(MeritPartial)),
                          [MeritPartial])
        self.assertMerits(s2._cleanfor(MeritPartial)
                          .translate(t._cleanfor(MeritPartial),
                                     d1._cleanfor(MeritPartial)),
                          [MeritPartial])
        self.assertMerits(s1._cleanfor(MeritNone)
                          .translate(t._cleanfor(MeritNone),
                                     d1._cleanfor(MeritNone)),
                          [])
        self.assertMerits(s2._cleanfor(MeritNone)
                          .translate(t._cleanfor(MeritNone),
                                     d1._cleanfor(MeritNone)),
                          [])

        self.assertMerits(s1._cleanfor(MeritFull).translate(t, d2),
                          [MeritFull])
        self.assertMerits(s2._cleanfor(MeritFull).translate(t, d2),
                          [MeritFull])
        self.assertMerits(s1._cleanfor(MeritPartial).translate(t, d2),
                          [])
        self.assertMerits(s2._cleanfor(MeritPartial).translate(t, d2),
                          [])
        self.assertMerits(s1._cleanfor(MeritPartial)
                          .translate(t._cleanfor(MeritPartial),
                                     d2._cleanfor(MeritPartial)),
                          [MeritPartial])
        self.assertMerits(s2._cleanfor(MeritPartial)
                          .translate(t._cleanfor(MeritPartial),
                                     d2._cleanfor(MeritPartial)),
                          [MeritPartial])
        self.assertMerits(s1._cleanfor(MeritNone)
                          .translate(t._cleanfor(MeritNone),
                                     d2._cleanfor(MeritNone)),
                          [])
        self.assertMerits(s2._cleanfor(MeritNone)
                          .translate(t._cleanfor(MeritNone),
                                     d2._cleanfor(MeritNone)),
                          [])

        self.assertMerits(s0._cleanfor(MeritFull)
                          .translate(t._cleanfor(MeritFull)), [MeritFull])
        self.assertMerits(s0._cleanfor(MeritFull).translate(t), [MeritFull])
        self.assertMerits(s0.translate(t, d2._cleanfor(MeritPartial)), [])
        self.assertMerits(s0._cleanfor(MeritNone)
                          .translate(t._cleanfor(MeritNone),
                                     d2._cleanfor(MeritNone)), [])

        self.assertClean(s1.translate(t, d1))
        self.assertClean(s2.translate(t, d1))
        self.assertClean(s1.translate(t, d2))
        self.assertClean(s2.translate(t, d2))
        self.assertClean(s1.translate(t))
        self.assertClean(s2.translate(t))
        self.assertClean(s0.translate(t))

def test_main():
    test_support.run_unittest(TaintTest, MeritsTest, UnaryStringOperationTest,
                              VariadicStringOperationTest)
