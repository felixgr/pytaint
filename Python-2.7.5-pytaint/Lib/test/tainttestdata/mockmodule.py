""" Test data for taint module patcher. """

class MockClass(object):
        def instance_source(self):
            return "abc"

        def instance_cleaner(self, s):
            return s

        def instance_sink(self, s):
            return True

class MeritX(Merit): pass
