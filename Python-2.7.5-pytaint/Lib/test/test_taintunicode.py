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
        t = u'\u0230'.taint()
        self.assertTainted(t)
        t = u't'.taint()
        self.assertTainted(t)

        tt = t.taint()
        self.assertTainted(tt)

        ttt = u'\u0230a longer string that will be tainted'.taint()
        self.assertTainted(ttt)

        u = u'\u0230'
        self.assertClean(u)

        self.assertEqual(u'\u0230x', u'\u0230x'.taint())
        self.assertEqual(u'\u0230a loooooooooooooooooooonger string', \
                         u'\u0230a loooooooooooooooooooonger string'.taint())

        self.assertTainted(u''.taint())
        self.assertClean(u'')
        self.assertTainted(u'\u0230x'.taint())
        self.assertClean(u'\u0230x')

    def test_from_string(self):
        u = unicode('ttttt')
        t = unicode('ttttt'.taint())
        t_full = unicode(u._cleanfor(MeritFull))
        t_part = unicode(u._cleanfor(MeritPartial))
        t_none = unicode(u._cleanfor(MeritNone))
        t_all = unicode(u._cleanfor(MeritFull)._cleanfor(MeritPartial)\
                 ._cleanfor(MeritNone))

        self.assertClean(u)
        self.assertTainted(t)
        self.assertTainted(t_full)
        self.assertTainted(t_part)
        self.assertTainted(t_none)
        self.assertTainted(t_all)

        self.assertMerits(u, None)
        self.assertMerits(t, [])
        self.assertMerits(t_full, [MeritFull])
        self.assertMerits(t_part, [MeritPartial])
        self.assertMerits(t_none, [MeritNone])
        self.assertMerits(t_all, [MeritFull, MeritPartial, MeritNone])

class MeritsTest(AbstractTaintTest):
    def test_propagate(self):
        t = u'\u0230ttttt'.taint()
        t_full = t._cleanfor(MeritFull)
        t_part = t._cleanfor(MeritPartial)
        t_none = t._cleanfor(MeritNone)
        t_all = t._cleanfor(MeritFull)._cleanfor(MeritPartial)\
                 ._cleanfor(MeritNone)

        s = u'\u0230sssss'
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
        t = u'\u0230\u0230ttttt'.taint()
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

        s = u'\u0230abcdef'
        s_full = s._cleanfor(MeritFull)
        s_part = s._cleanfor(MeritNone)
        s_none = s._cleanfor(MeritNone)
        s_all = s._cleanfor(MeritFull)._cleanfor(MeritPartial)\
                 ._cleanfor(MeritNone)

        u = u'\u0230uuuuu'
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
        t = u'\u0230ttttt'.taint()
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

        s = u'\u0230abcdef'
        s_full = s._cleanfor(MeritFull)
        s_part = s._cleanfor(MeritNone)
        s_none = s._cleanfor(MeritNone)
        s_all = s._cleanfor(MeritFull)._cleanfor(MeritPartial)\
                 ._cleanfor(MeritNone)

        u = u'\u0230uuuuu'

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
        t = u'\u0230ttttt'.taint()
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

        s = u'\u0230abcdef'
        s_full = s._cleanfor(MeritFull)
        s_part = s._cleanfor(MeritNone)
        s_none = s._cleanfor(MeritNone)
        s_all = s._cleanfor(MeritFull)._cleanfor(MeritPartial)\
                 ._cleanfor(MeritNone)

        u = u'\u0230uuuuu'

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
        t = u'\u0230ttttt'.taint()
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

        s = u'\u0230abcdef'
        s_full = s._cleanfor(MeritFull)
        s_part = s._cleanfor(MeritNone)
        s_none = s._cleanfor(MeritNone)
        s_all = s._cleanfor(MeritFull)._cleanfor(MeritPartial)\
                 ._cleanfor(MeritNone)

        u = u'\u0230uuuuu'

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

class UnaryUnicodeOperationTest(AbstractTaintTest):
    """ Test string methods which use only one string argument - ie. where
    taint is just copied from the argument to result. """

    def test_repeat(self):
        self.assertTainted(u'\u0230bcd'.taint() * 0)
        self.assertTainted(u''.taint() * 100)
        self.assertTainted(u'\u0230BCD asdf'.taint() * 15)
        self.assertTainted(u'\u0230 am very long'.taint() * 10000)

        self.assertTainted(u'\u0230bcd'._cleanfor(MeritFull) * 0)
        self.assertTainted(u''._cleanfor(MeritFull) * 100)
        self.assertTainted(u'\u0230BCD asdf'._cleanfor(MeritFull) * 15)
        self.assertTainted(u'\u0230 am very long'._cleanfor(MeritFull) * 10000)

        self.assertTainted(u'\u0230bcd'._cleanfor(MeritPartial) * 0)
        self.assertTainted(u''._cleanfor(MeritPartial) * 100)
        self.assertTainted(u'\u0230BCD asdf'._cleanfor(MeritPartial) * 15)
        self.assertTainted(u'\u0230 am very long'._cleanfor(MeritPartial) * 10000)

        self.assertTainted(u'\u0230bcd'._cleanfor(MeritNone) * 0)
        self.assertTainted(u''._cleanfor(MeritNone) * 100)
        self.assertTainted(u'\u0230BCD asdf'._cleanfor(MeritNone) * 15)
        self.assertTainted(u'\u0230 am very long'._cleanfor(MeritNone) * 10000)

        self.assertClean(u'\u0230bcd' * 0)
        self.assertClean(u'' * 100)
        self.assertClean(u'\u0230BCD' * 5)
        self.assertClean(u'\u0230 very long string' * 10000)

    def test_item(self):
        u = u'\u0230aaa'
        t = u'\u0230aaa'.taint()
        c = u'\u0230aaa'._cleanfor(MeritFull)
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
        u = u'\u0230aaaaaaaa'
        t = u'\u0230tttttttt'.taint()
        c = u'\u0230cccccccc'._cleanfor(MeritFull)

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
        u = u'\u0230aaaaaaaa'
        t = u'\u0230tttttttt'.taint()
        c = u'\u0230cccccccc'._cleanfor(MeritFull)

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
        self.assertTainted(u'\u0230bcd'.taint().lower())
        self.assertTainted(u'\u0230BCd 123'._cleanfor(MeritFull).lower())
        self.assertTainted(u'\u0230BCD'.taint()._cleanfor(MeritNone).lower())
        self.assertTainted(u'\u0230BCD XYZ'.taint().lower())
        self.assertTainted(''.taint().lower())
        self.assertTainted(u'\u0230  3   \n\n'.taint().lower())

        self.assertClean(u'\u0230bcd'.lower())
        self.assertClean(u'\u0230BCd 123'.lower())
        self.assertClean(u'\u0230BCD'.lower())
        self.assertClean(u'\u0230BCD XYZ'.lower())
        self.assertClean(''.lower())
        self.assertClean(u'\u0230  3   \n\n'.lower())

    def test_upper(self):
        self.assertTainted(u'\u0230bcd'.taint().upper())
        self.assertTainted(u'\u0230BCd 123'._cleanfor(MeritFull).upper())
        self.assertTainted(u'\u0230BCD'.taint()._cleanfor(MeritNone).upper())
        self.assertTainted(u'\u0230BCD XYZ'.taint().upper())
        self.assertTainted(''.taint().upper())
        self.assertTainted(u'\u0230  3   \n\n'.taint().upper())

        self.assertClean(u'\u0230bcd'.upper())
        self.assertClean(u'\u0230BCd 123'.upper())
        self.assertClean(u'\u0230BCD'.upper())
        self.assertClean(u'\u0230BCD XYZ'.upper())
        self.assertClean(''.upper())
        self.assertClean(u'\u02301  3   \n\n'.upper())

    def test_title(self):
        self.assertTainted(u'\u0230bcd'.taint().title())
        self.assertTainted(u'\u0230BCd 123'._cleanfor(MeritFull).title())
        self.assertTainted(u'\u0230BCD'.taint()._cleanfor(MeritNone).title())
        self.assertTainted(u'\u0230BCD XYZ'.taint().title())
        self.assertTainted(''.taint().title())
        self.assertTainted(u'\u0230  3   \n\n'.taint().title())

        self.assertClean(u'\u0230bcd'.title())
        self.assertClean(u'\u0230BCd 123'.title())
        self.assertClean(u'\u0230BCD'.title())
        self.assertClean(u'\u0230BCD XYZ'.title())
        self.assertClean('u'.title())
        self.assertClean(u'\u0230  3   \n\n'.title())

    def test_capitalize(self):
        self.assertTainted(u'\u0230abcd'.taint().title())
        self.assertTainted(u'\u0230aBCd qwer asafd'._cleanfor(MeritFull).title())
        self.assertTainted(u'\u0230ABCD'.taint()._cleanfor(MeritNone).title())
        self.assertTainted(u'\u0230ABCD XYZ'.taint().title())
        self.assertTainted(''.taint().title())
        self.assertTainted(u'\u0230asdf zxcv \n hjkl\n'.taint().title())

        self.assertClean(u'\u0230abcd'.title())
        self.assertClean(u'\u0230aBCd 123'.title())
        self.assertClean(u'\u0230ABCD'.title())
        self.assertClean(u'\u0230ABCD XYZ HJKL'.title())
        self.assertClean(''.title())
        self.assertClean(u'\u02301  3   \n\n'.title())

    def test_zfill(self):
        self.assertTainted(u'12'.taint().zfill(10))
        self.assertTainted(u'+1234'.taint().zfill(10))
        self.assertTainted(u'-1234'.taint().zfill(2))
        self.assertTainted(u''.taint().zfill(10))
        self.assertTainted(u'400400'.taint().zfill(3))
        self.assertTainted(u'123.432'.taint().zfill(10))

        self.assertTainted(u'23400000'._cleanfor(MeritNone).zfill(100))
        self.assertTainted(u'34434234'._cleanfor(MeritNone).zfill(3))
        self.assertTainted(u'-123234234'._cleanfor(MeritPartial).zfill(100))
        self.assertTainted(u'-999342'._cleanfor(MeritPartial).zfill(3))
        self.assertTainted(u'345555.4663'._cleanfor(MeritFull).zfill(100))
        self.assertTainted(u'3456765.466654'.\
                           _cleanfor(MeritFull).zfill(3))

        self.assertClean(u'234'.zfill(2))
        self.assertClean(u'-1453'.zfill(20))
        self.assertClean(u'1345.3345'.zfill(2))
        self.assertClean(u'6456.34354'.zfill(20))
        self.assertClean(u'-9999.5345'.zfill(2))
        self.assertClean(u'-1000.11234'.zfill(20))

        self.assertTainted(u''.taint().zfill(1))
        self.assertClean(u'')

    def test_expandtabs(self):
        self.assertTainted(u''.taint().expandtabs())
        self.assertTainted(u'\t'.taint().expandtabs())
        self.assertTainted(u'ab\u0230cd \t qwer'.taint().expandtabs())
        self.assertTainted(u'\t\tAB\u0230CD'.taint().expandtabs())
        self.assertTainted(u'ABCD\tXYZ'.taint().expandtabs())
        self.assertTainted(u'asdf\t123@:\u0230#$L zxcv \t\t hjkl\n'.taint().expandtabs())

        self.assertTainted(u''._cleanfor(MeritFull).expandtabs())
        self.assertTainted(u'\t'._cleanfor(MeritFull).expandtabs())
        self.assertTainted(u'abcd \t qwer'._cleanfor(MeritNone).expandtabs())
        self.assertTainted(u'\t\tAB\u0230CD'._cleanfor(MeritNone).expandtabs())
        self.assertTainted(u'ABCD\tXYZ'._cleanfor(MeritPartial).expandtabs())
        self.assertTainted(u'asdf\t123@:\u0230#$L zxcv \t\t hjkl\n'.\
                           _cleanfor(MeritPartial).expandtabs())

        self.assertClean(u''.expandtabs())
        self.assertClean(u'\t'.expandtabs())
        self.assertClean(u'abcd \t qw\u0230er'.expandtabs())
        self.assertClean(u'\t\tABCD'.expandtabs())
        self.assertClean(u'ABCD\t\u0230XYZ'.expandtabs())
        self.assertClean(u'asdf\t123@:#$L zxcv \t\t hjkl\n'.expandtabs())

    def test_swapcase(self):
        self.assertTainted(u'\u0230abcd'.taint().swapcase())
        self.assertTainted(u'\u0230aBCd 123'._cleanfor(MeritFull).swapcase())
        self.assertTainted(u'\u0230ABCD'.taint()._cleanfor(MeritNone).swapcase())
        self.assertTainted(u'\u0230ABcd xyZ'.taint().swapcase())
        self.assertTainted(''.taint().swapcase())
        self.assertTainted(u'\u02301  3   \n\n'.taint().swapcase())

        self.assertClean(u'\u0230abcd'.swapcase())
        self.assertClean(u'\u0230aBCd 123'.swapcase())
        self.assertClean(u'\u0230aBCD'.swapcase())
        self.assertClean(u'\u0230Abcd Xyz'.swapcase())
        self.assertClean(''.swapcase())
        self.assertClean(u'\u02301  3   \n\n'.swapcase())

    def test_coding(self):
        ut = u'ttttttt'
        self.assertClean(str(ut))
        self.assertMerits(str(ut.taint()), [])
        self.assertMerits(str(ut._cleanfor(MeritFull)), [MeritFull])
        self.assertMerits(str(ut._cleanfor(MeritFull)._cleanfor(MeritNone)),
                          [MeritFull, MeritNone])
        self.assertClean(str(u''))
        self.assertMerits(str(u''.taint()), [])
        self.assertMerits(str(u''._cleanfor(MeritFull)), [MeritFull])
        self.assertMerits(str(u''._cleanfor(MeritFull)._cleanfor(MeritNone)),
                          [MeritFull, MeritNone])
        self.assertClean(unicode(ut))
        self.assertMerits(unicode(ut.taint()), [])
        self.assertMerits(unicode(ut._cleanfor(MeritFull)), [MeritFull])
        self.assertMerits(unicode(ut._cleanfor(MeritFull)._cleanfor(MeritNone)),
                          [MeritFull, MeritNone])
        self.assertClean(unicode(u''))
        self.assertMerits(unicode(u''.taint()), [])
        self.assertMerits(unicode(u''._cleanfor(MeritFull)), [MeritFull])
        self.assertMerits(unicode(u''._cleanfor(MeritFull)._cleanfor(MeritNone)),
                          [MeritFull, MeritNone])

        st = 'ttttttt'
        self.assertClean(unicode(st))
        self.assertMerits(unicode(st.taint()), [])
        self.assertMerits(unicode(st._cleanfor(MeritFull)), [MeritFull])
        self.assertMerits(unicode(st._cleanfor(MeritFull)._cleanfor(MeritNone)),
                          [MeritFull, MeritNone])
        self.assertClean(unicode(''))
        self.assertMerits(unicode(''.taint()), [])
        self.assertMerits(unicode(''._cleanfor(MeritFull)), [MeritFull])
        self.assertMerits(unicode(''._cleanfor(MeritFull)._cleanfor(MeritNone)),
                          [MeritFull, MeritNone])

        ab = u'\x41\x42'
        self.assertClean(ab.decode())
        self.assertTainted(ab.taint().decode())
        self.assertMerits(ab._cleanfor(MeritFull).decode(),
                          [MeritFull])
        self.assertMerits(ab._cleanfor(MeritPartial).decode(),
                          [MeritPartial])
        self.assertMerits(ab._cleanfor(MeritNone)._cleanfor(MeritFull).decode(),
                          [MeritFull, MeritNone])

        self.assertClean(ab.encode())
        self.assertTainted(ab.taint().encode())
        self.assertMerits(ab._cleanfor(MeritFull).encode(),
                          [MeritFull])
        self.assertMerits(ab._cleanfor(MeritPartial).encode(),
                          [MeritPartial])
        self.assertMerits(ab._cleanfor(MeritNone)._cleanfor(MeritFull).encode(),
                          [MeritFull, MeritNone])

        default_encoding = sys.getdefaultencoding()
        for coding in ['utf-8', 'latin-1', 'ascii', 'utf-7', 'mbcs']:
            # sys needs to be reloaded before changing encoding
            reload(sys)
            try:
                sys.setdefaultencoding(coding)
            except LookupError: # mbcs will work only on Windows
                continue
            self.assertClean(ab.decode())
            self.assertTainted(ab.taint().decode())
            self.assertMerits(ab._cleanfor(MeritFull).decode(),
                              [MeritFull])
            self.assertMerits(ab._cleanfor(MeritPartial).decode(),
                              [MeritPartial])
            self.assertMerits(ab._cleanfor(MeritNone)._cleanfor(MeritFull)
                              .decode(),
                              [MeritFull, MeritNone])

            self.assertClean(ab.encode())
            self.assertTainted(ab.taint().encode())
            self.assertMerits(ab._cleanfor(MeritFull).encode(),
                              [MeritFull])
            self.assertMerits(ab._cleanfor(MeritPartial).encode(),
                              [MeritPartial])
            self.assertMerits(ab._cleanfor(MeritNone)._cleanfor(MeritFull)
                              .encode(),
                              [MeritFull, MeritNone])
        reload(sys)
        sys.setdefaultencoding(default_encoding)


class VariadicUnicodeOperationTest(AbstractTaintTest):
    """ Test unicode operations that take more than one argument and where
    the propagation semantics is applied. """
    def test_concatenation(self):
        a = u'\u0230aaa'.taint()
        b = 'bbb'.taint()
        u = u'\u0230ccc'
        self.assertTainted(a + b)
        self.assertTainted(a + u)
        self.assertTainted(u + a)
        self.assertTainted(u + b)
        self.assertTainted(b + u)
        self.assertClean(u + u)

    def test_rpartition(self):
        t = u't  t t tt   tt'.taint()
        u = u'u  uu   uuu   uuuu  u'
        a = u'a  aa aa a    a'._cleanfor(MeritFull)
        b = 'b bbb   bb b'._cleanfor(MeritNone)
        c = u._cleanfor(MeritFull)._cleanfor(MeritNone).\
              _cleanfor(MeritPartial)
        ss = u'  '
        tt = u'  '.taint()

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
        t = u't  t t tt   tt'.taint()
        u = u'u  uu   uuu   uuuu  u'
        a = u'a  aa aa a    a'._cleanfor(MeritFull)
        b = 'b bbb   bb b'._cleanfor(MeritNone)
        c = u._cleanfor(MeritFull)._cleanfor(MeritNone).\
              _cleanfor(MeritPartial)
        ss = u'  '
        tt = u'  '.taint()

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
        t = u'   t  t t tt   tt'.taint()
        u = u'u  uu   uuu   uuuu  u'
        a = u'a  aa aa a    a'._cleanfor(MeritFull)
        b = 'b bbb   bb b'._cleanfor(MeritNone)
        c = u._cleanfor(MeritFull)._cleanfor(MeritNone)

        x = u'xy'
        y = 'xy'.taint()
        z = u'xy'._cleanfor(MeritPartial)

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
        t = u'   t  t t tt   tt'.taint()
        u = u'u  uu   uuu   uuuu  u'
        a = u'a  aa aa a    a'._cleanfor(MeritFull)
        b = 'b bbb   bb b'._cleanfor(MeritNone)
        c = u._cleanfor(MeritFull)._cleanfor(MeritNone)

        x = u'xy'
        y = 'xy'.taint()
        z = u'xy'._cleanfor(MeritPartial)

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
        t = u'   t  t t tt   tt'.taint()
        u = u'u  uu   uuu   uuuu  u'
        a = u'a  aa aa a    a'._cleanfor(MeritFull)
        b = 'b bbb   bb b'._cleanfor(MeritNone)
        c = u._cleanfor(MeritFull)._cleanfor(MeritNone)

        x = u'xy'
        y = 'xy'.taint()
        z = u'xy'._cleanfor(MeritPartial)

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
        pass

    def test_rjust(self):
        pass

    def test_center(self):
        pass

    def test_replace(self):
        s = u'abc def def def'
        a = u'def'
        b = u'xyz'
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

        self.assertTainted(u'u'.replace(u'x', u''.taint()))
        self.assertClean(u'u')
        self.assertTainted(u'u'.replace(u'x'.taint(), u''))
        self.assertClean(u'u')
        self.assertTainted(u'u'.taint().replace(u'x', u''))
        self.assertClean(u'u')

    def test_split(self):
        t = u't  t t tt   tt'.taint()
        u = u'u  uu   uuu   uuuu  u'
        a = u'a  aa aa a    a'._cleanfor(MeritFull)
        b = 'b bbb   bb b'._cleanfor(MeritNone)
        c = u._cleanfor(MeritFull)._cleanfor(MeritNone)\
              ._cleanfor(MeritPartial)
        ss = u'  '

        [self.assertTainted(x) for x in t.split()]
        [self.assertTainted(x) for x in a.split()]
        [self.assertTainted(x) for x in b.split()]
        [self.assertTainted(x) for x in c.split()]
        [self.assertClean(x) for x in u.split()]

        [self.assertTainted(x) for x in t.split(u' ')]
        [self.assertTainted(x) for x in a.split(u' ')]
        [self.assertTainted(x) for x in b.split(u' ')]
        [self.assertTainted(x) for x in c.split(u' ')]
        [self.assertClean(x) for x in u.split(u' ')]

        [self.assertTainted(x) for x in t.split(u' '.taint())]
        [self.assertTainted(x) for x in a.split(u' '.taint())]
        [self.assertTainted(x) for x in b.split(u' '.taint())]
        [self.assertTainted(x) for x in c.split(u' '.taint())]
        [self.assertTainted(x) for x in u.split(u' '.taint())]

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
                           c.split(u' '._cleanfor(MeritPartial))]

    def test_rsplit(self):
        t = u't  t t tt   tt'.taint()
        u = u'u  uu   uuu   uuuu  u'
        a = u'a  aa aa a    a'._cleanfor(MeritFull)
        b = 'b bbb   bb b'._cleanfor(MeritNone)
        c = u._cleanfor(MeritFull)._cleanfor(MeritNone).\
              _cleanfor(MeritPartial)
        ss = u'  '

        [self.assertTainted(x) for x in t.rsplit()]
        [self.assertTainted(x) for x in a.rsplit()]
        [self.assertTainted(x) for x in b.rsplit()]
        [self.assertTainted(x) for x in c.rsplit()]
        [self.assertClean(x) for x in u.rsplit()]

        [self.assertTainted(x) for x in t.rsplit(u' ')]
        [self.assertTainted(x) for x in a.rsplit(u' ')]
        [self.assertTainted(x) for x in b.rsplit(u' ')]
        [self.assertTainted(x) for x in c.rsplit(u' ')]
        [self.assertClean(x) for x in u.rsplit(u' ')]

        [self.assertTainted(x) for x in t.rsplit(u' '.taint())]
        [self.assertTainted(x) for x in a.rsplit(u' '.taint())]
        [self.assertTainted(x) for x in b.rsplit(u' '.taint())]
        [self.assertTainted(x) for x in c.rsplit(u' '.taint())]
        [self.assertTainted(x) for x in u.rsplit(u' '.taint())]

        [self.assertTainted(x) for x in t.split(' '.taint())]
        [self.assertTainted(x) for x in a.split(' '.taint())]
        [self.assertTainted(x) for x in b.split(' '.taint())]
        [self.assertTainted(x) for x in c.split(' '.taint())]
        [self.assertTainted(x) for x in u.split(' '.taint())]

        [self.assertTainted(x) for x in t.rsplit(ss)]
        [self.assertTainted(x) for x in a.rsplit(ss)]
        [self.assertTainted(x) for x in b.rsplit(ss)]
        [self.assertTainted(x) for x in c.rsplit(ss)]
        [self.assertClean(x) for x in u.rsplit(ss)]

        [self.assertMerits(x, [MeritPartial]) for x in \
                           c.rsplit(u' '._cleanfor(MeritPartial))]

    def test_splitlines(self):
        t = u't \n t\n t tt \n\n\n  tt'.taint()
        u = u'\nu  uu n\n\n \n  uuuu  u'
        a = u'\n\na \n aa aa a  \n\n  a'._cleanfor(MeritFull)
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

    def test_format_operator(self):
        # test formatting using the % operator
        t = u'ttttt'.taint()
        ts = 'ttttt'.taint()
        t_full = t._cleanfor(MeritFull)
        t_part = t._cleanfor(MeritPartial)
        t_none = t._cleanfor(MeritNone)
        t_all = t._cleanfor(MeritFull)._cleanfor(MeritPartial)\
                 ._cleanfor(MeritNone)

        fmt = u'%s %s %s %%'
        fmt_taint = fmt.taint()
        fmt_full = fmt_taint._cleanfor(MeritFull)
        fmt_part = fmt_taint._cleanfor(MeritPartial)
        fmt_none = fmt_taint._cleanfor(MeritNone)
        fmt_all = fmt_full._cleanfor(MeritPartial)._cleanfor(MeritNone)

        self.assertClean(fmt % (u'a', u'b', u'c'))
        self.assertTainted(fmt_taint % (u'a', u'b', u'c'))
        self.assertTainted(fmt_taint % (t, t, t))
        self.assertTainted(fmt % (u'a', u'b', t))
        self.assertTainted(fmt % (t, u'b', t))
        self.assertTainted(fmt % (u'a', t, u'b'))

        self.assertMerits(fmt % (t, u'a', t_full), [])
        self.assertMerits(fmt % (u'b', u'a', t_full), [MeritFull])
        self.assertMerits(fmt % (t_all , t_full, u'a'), [MeritFull])
        self.assertMerits(fmt_taint % (t, u'a', t_full), [])
        self.assertMerits(fmt_taint % (u'b', u'a', t_full), [])
        self.assertMerits(fmt_taint % (t_all , t_full, u'a'), [])

        self.assertMerits(fmt % (str(t), str(u'a'), str(t_full)), [])
        self.assertMerits(fmt % (str(u'b'), str(u'a'), str(t_full)), [MeritFull])
        self.assertMerits(fmt % (str(t_all ), str(t_full), str(u'a')), [MeritFull])
        self.assertMerits(fmt_taint % (str(t), str(u'a'), str(t_full)), [])
        self.assertMerits(fmt_taint % (str(u'b'), str(u'a'), str(t_full)), [])
        self.assertMerits(fmt_taint % (str(t_all ), str(t_full), str(u'a')), [])

        self.assertMerits(fmt_full % (t_all , t_full, u'a'), [MeritFull])
        self.assertMerits(fmt_all % (t_all , t_full, u'a'), [MeritFull])
        self.assertMerits(fmt_part % (t_part , t_all, t_all), [MeritPartial])
        self.assertMerits(fmt_all % (t_all, t_part, t_all), [MeritPartial])
        self.assertMerits(fmt_none % (t_none , t_all, u'c'), [])
        self.assertMerits(fmt_all % (t_all, t_none, t_all), [])

        self.assertMerits(fmt % ('t'.taint(), u'a', t_full), [])
        self.assertMerits(fmt % (u'b', 'a', t_full), [MeritFull])
        self.assertMerits(fmt % (t_all , t_full, 'a'), [MeritFull])
        self.assertMerits(fmt_taint % (t, 'a', t_full), [])
        self.assertMerits(fmt_taint % (u'b', u'a', 't'._cleanfor(MeritFull)), [])

    def test_format_method(self):
        # test formatting using the format method
        t = u'ttttt'.taint()
        t_full = t._cleanfor(MeritFull)
        t_part = t._cleanfor(MeritPartial)
        t_none = t._cleanfor(MeritNone)
        t_all = t._cleanfor(MeritFull)._cleanfor(MeritPartial)\
                 ._cleanfor(MeritNone)

        fmt = u'{} {} {} {{}}'
        fmt_taint = fmt.taint()
        fmt_full = fmt_taint._cleanfor(MeritFull)
        fmt_part = fmt_taint._cleanfor(MeritPartial)
        fmt_none = fmt_taint._cleanfor(MeritNone)
        fmt_all = fmt_full._cleanfor(MeritPartial)._cleanfor(MeritNone)

        self.assertClean(fmt.format(u'a', u'b', u'c'))

        # TODO(marcinf) specification says that result of below operation
        # should be tainted. However, since the last argument (u'd') is not
        # interpolated into format string, it is clean. Change the docs
        # accordingly to mention that taint is propagated only across the
        # relevant arguments.
        self.assertClean(fmt.format(u'a', u'b', u'c', u'd'.taint()))

        self.assertTainted(fmt_taint.format(u'a', u'b', u'c'))
        self.assertTainted(fmt_taint.format(t, t, t))
        self.assertTainted(fmt.format(u'a', u'b', t))
        self.assertTainted(fmt.format(t, u'b', t))
        self.assertTainted(fmt.format(u'a', t, u'b'))

        self.assertMerits(fmt.format(t, u'a', t_full), [])
        self.assertMerits(fmt.format(u'b', u'a', t_full), [MeritFull])
        self.assertMerits(fmt.format(t_all , t_full, u'a'), [MeritFull])
        self.assertMerits(fmt_taint.format(t, u'a', t_full), [])
        self.assertMerits(fmt_taint.format(u'b', u'a', t_full), [])
        self.assertMerits(fmt_taint.format(t_all , t_full, u'a'), [])

        self.assertMerits(fmt_full.format(t_all , t_full, u'a'), [MeritFull])
        self.assertMerits(fmt_all.format(t_all , t_full, u'a'), [MeritFull])
        self.assertMerits(fmt_part.format(t_part , t_all, t_all),
                          [MeritPartial])
        self.assertMerits(fmt_all.format(t_all, t_part, t_all),
                          [MeritPartial])
        self.assertMerits(fmt_none.format(t_none , t_all, u'c'), [])
        self.assertMerits(fmt_all.format(t_all, t_none, t_all), [])

        fmt = u'{2} {0} {1} {{}}'
        fmt_taint = fmt.taint()
        fmt_full = fmt_taint._cleanfor(MeritFull)
        fmt_part = fmt_taint._cleanfor(MeritPartial)
        fmt_none = fmt_taint._cleanfor(MeritNone)
        fmt_all = fmt_full._cleanfor(MeritPartial)._cleanfor(MeritNone)

        self.assertClean(fmt.format(u'a', u'b', u'c'))
        self.assertClean(fmt.format(u'a', u'b', u'c', u'd'.taint()))
        self.assertTainted(fmt_taint.format(u'a', u'b', u'c'))
        self.assertTainted(fmt_taint.format(t, t, t))
        self.assertTainted(fmt.format(u'a', u'b', t))
        self.assertTainted(fmt.format(t, u'b', t))
        self.assertTainted(fmt.format(u'a', t, u'b'))

        self.assertMerits(fmt.format(t, u'a', t_full), [])
        self.assertMerits(fmt.format(u'b', u'a', t_full), [MeritFull])
        self.assertMerits(fmt.format(t_all , t_full, u'a'), [MeritFull])
        self.assertMerits(fmt_taint.format(t, u'a', t_full), [])
        self.assertMerits(fmt_taint.format(u'b', u'a', t_full), [])
        self.assertMerits(fmt_taint.format(t_all , t_full, u'a'), [])

        self.assertMerits(fmt_full.format(t_all , t_full, u'a'), [MeritFull])
        self.assertMerits(fmt_all.format(t_all , t_full, u'a'), [MeritFull])
        self.assertMerits(fmt_part.format(t_part , t_all, t_all),
                          [MeritPartial])
        self.assertMerits(fmt_all.format(t_all, t_part, t_all),
                          [MeritPartial])
        self.assertMerits(fmt_none.format(t_none , t_all, u'c'), [])
        self.assertMerits(fmt_all.format(t_all, t_none, t_all), [])

        fmt = u'{x} {y[0]} {z.t} {{}}'
        fmt_taint = fmt.taint()
        fmt_full = fmt_taint._cleanfor(MeritFull)
        fmt_part = fmt_taint._cleanfor(MeritPartial)
        fmt_none = fmt_taint._cleanfor(MeritNone)
        fmt_all = fmt_full._cleanfor(MeritPartial)._cleanfor(MeritNone)

        def pack(x):
            """ Create a dummy object d satisfying d.t == x. This is for
            testing formatting string with objects' attributes. """
            return type('zt', (), {'t': x})

        self.assertClean(fmt.format(x=u'a', y=[u'b'], z=pack(u'c')))
        self.assertClean(fmt.format(x=u'a', y=[u'b'], z=pack(u'c'),
                                    t=u'd'.taint()))
        self.assertTainted(fmt_taint.format(x=u'a', y=[u'b'], z=pack(u'c')))
        self.assertTainted(fmt_taint.format(x=t, y=[t], z=pack(t)))
        self.assertTainted(fmt.format(x=u'a', y=[u'b'], z=pack(t)))
        self.assertTainted(fmt.format(x=t, y=[u'b'], z=pack(t)))
        self.assertTainted(fmt.format(x=u'a', y=[t], z=pack(u'b')))

        self.assertMerits(fmt.format(x=t, y=[u'a'], z=pack(t_full)),
                          [])
        self.assertMerits(fmt.format(x=u'b', y=[u'a'], z=pack(t_full)),
                          [MeritFull])
        self.assertMerits(fmt.format(x=t_all , y=[t_full], z=pack(u'a')),
                          [MeritFull])
        self.assertMerits(fmt_taint.format(x=t, y=[u'a'], z=pack(t_full)),
                          [])
        self.assertMerits(fmt_taint.format(x=u'b', y=[u'a'], z=pack(t_full)),
                          [])
        self.assertMerits(fmt_taint.format(x=t_all , y=[t_full], z=pack(u'a')),
                          [])

        self.assertMerits(fmt_full.format(x=t_all , y=[t_full], z=pack(u'a')),
                          [MeritFull])
        self.assertMerits(fmt_all.format(x=t_all , y=[t_full], z=pack(u'a')),
                          [MeritFull])
        self.assertMerits(fmt_part.format(x=t_part , y=[t_all], z=pack(t_all)),
                          [MeritPartial])
        self.assertMerits(fmt_all.format(x=t_all, y=[t_part], z=pack(t_all)),
                          [MeritPartial])
        self.assertMerits(fmt_none.format(x=t_none , y=[t_all], z=pack(u'c')),
                          [])
        self.assertMerits(fmt_all.format(x=t_all, y=[t_none], z=pack(t_all)),
                          [])

        nested = u'{0:{a}}'
        self.assertMerits(nested.taint().format(u't', a=u's'), [])
        self.assertMerits(nested._cleanfor(MeritFull).format(u't', a=u's'),
                          [MeritFull])
        self.assertMerits(nested._cleanfor(MeritPartial).format(u't', a=u's'),
                          [])
        self.assertMerits(nested._cleanfor(MeritPartial).format(
                                    t_part, a=u's'._cleanfor(MeritPartial)),
                          [MeritPartial])
        self.assertMerits(nested._cleanfor(MeritNone).format(
                                    t_none, a=u's'._cleanfor(MeritNone)),
                          [])

    def test_join(self):
        t = u'\u0230ttttt'.taint()
        u = u'\u0230uuuuu'
        a = 'aaaaa'._cleanfor(MeritFull)
        b = u'\u0230bbbbb'._cleanfor(MeritNone)
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

        self.assertTainted(t.join([u'a']))
        self.assertTainted(a.join([u'a']))
        self.assertTainted(b.join([u'a']))
        self.assertTainted(c.join([u'a']))
        self.assertClean(u.join([u'a']))

        self.assertTainted(t.join(['a', u'']))
        self.assertTainted(a.join([u'', 'a']))
        self.assertTainted(b.join(['a', u'']))
        self.assertTainted(c.join(['', 'a', u'']))
        self.assertClean(u.join(['a', u'']))

        self.assertTainted(t.join(['']))
        self.assertTainted(a.join(['', '']))
        self.assertTainted(c.join(['', '', '']))
        self.assertClean(u.join(['', u'', '', '', '']))
        self.assertTainted(u.join(['', u''.taint(), '', '', '', '']))
        self.assertTainted(u.join([''._cleanfor(MeritFull), '', '', '']))
        self.assertTainted(u.join(['', u'', t]))

        self.assertTainted(t.join([u'a', 'xx']))
        self.assertTainted(t.join([u'aaaaaaaaaaaa']))
        self.assertTainted(a.join([u'b', 'axxxk']))
        self.assertTainted(b.join([u'a', 'aa', 'f', 'g', 'h', 'r']))
        self.assertTainted(c.join([u'c', 'afff', 'dddd']))
        self.assertClean(u.join([u'aaaa']))
        self.assertClean(u.join(['aa', u'bb', 'cc', 'd']))
        self.assertTainted(u.join([u'aa'.taint(), 'bb', u'cc', 'd']))
        self.assertTainted(u.join(['aa', u'bb'._cleanfor(MeritFull),\
                                   'cc'._cleanfor(MeritNone), 'd']))

    def test_translate(self):
        s1 = u'abcdef'
        s1_t = u'abcdef'.taint()
        s1_full = u'abcdef'._cleanfor(MeritFull)
        s1_part = u'abcdef'._cleanfor(MeritPartial)
        s1_none = u'abcdef'._cleanfor(MeritNone)
        s2 = u'ghijkl'
        t1 = {97 : None,
              98 : u'x'}
        tp = {97 : u'y'._cleanfor(MeritPartial),
              98 : u'x'._cleanfor(MeritPartial)}
        tf = {97 : u'y'._cleanfor(MeritFull),
              98 : u'x'._cleanfor(MeritFull)}
        tn = {97 : u'y'._cleanfor(MeritFull),
              98 : u'x'._cleanfor(MeritNone)}

        self.assertClean(s1.translate(t1))
        self.assertMerits(s1.translate(tf), [MeritFull])
        self.assertMerits(s1.translate(tp), [])
        self.assertMerits(s1.translate(tn), [])

        self.assertTainted(s1_t.translate(t1))
        self.assertMerits(s1_t.translate(tf), [])
        self.assertMerits(s1_t.translate(tp), [])
        self.assertMerits(s1_t.translate(tn), [])

        self.assertTainted(s1_full.translate(t1))
        self.assertMerits(s1_full.translate(tf), [MeritFull])
        self.assertMerits(s1_full.translate(tp), [])
        self.assertMerits(s1_full.translate(tn), [])

        self.assertTainted(s1_part.translate(t1))
        self.assertMerits(s1_part.translate(tf), [])
        self.assertMerits(s1_part.translate(tp), [MeritPartial])
        self.assertMerits(s1_part.translate(tn), [])

        self.assertTainted(s1_none.translate(t1))
        self.assertMerits(s1_none.translate(tf), [])
        self.assertMerits(s1_none.translate(tp), [])
        self.assertMerits(s1_none.translate(tn), [])

        self.assertClean(s2.translate(t1))
        self.assertClean(s2.translate(tf))
        self.assertClean(s2.translate(tp))
        self.assertClean(s2.translate(tn))

def test_main():
    test_support.run_unittest(TaintTest, MeritsTest, UnaryUnicodeOperationTest,
                              VariadicUnicodeOperationTest)
