# Copyright 2013 Google Inc. All Rights Reserved.
#

"""Taint module - utilities and patching for taint tracking."""


import json
import itertools
import sys
import types
import re
from inspect import currentframe, getouterframes
from contextlib import contextmanager
from functools import wraps

__author__ = "Marcin Fatyga"


def source(func):
    """Turn function f into a taint source.

    Given a function returning a taintable object (either string/unicode or
    a collection of them), a new function returning a tainted string will be
    produced. The __name__ and __doc__ attributes of new function will be the
    same as in the old one. Supported collections are builtins - list, tuple,
    set, frozenset and dictionary (note - when tainting a dictionary, only
    values are tainted; keys are not modified). Collections are tainted
    recursively.

    Args:
        f: Function returning a string or collections of strings.

    Returns:
        string: A tainted string or string collection.

    """

    if not callable(func):
        return _taint_object(func)

    @wraps(func)
    def inner(*args, **kwargs):
        result = func(*args, **kwargs)
        return _taint_object(result)

    return inner


def _patch_sources(config, frame):
    """Create all taint sources specified in config for a given frame."""

    for s in config.get(u"sources", ()):
        namespace, target = _get_namespace_and_target(s, frame)
        apply_patch(namespace, target, source)


def cleaner(merit):
    """Create decorator to turn function into a taint cleaner for the merit."""

    def inner_cleaner(func):
        """Turn function f into a cleaner.

        Make the return of value function safe for operations requiring given
        merit.

        Args:
            f: function which will be a cleaner

        Returns:
            function: a cleaner for given merit
        """

        @wraps(func)
        def inner(*args, **kwargs):
            r = func(*args, **kwargs)
            return r._cleanfor(merit)

        return inner

    return inner_cleaner


def _patch_cleaners(config, frame):
    """Create all cleaners specified in config for a given frame."""
    if not u"cleaners" in config:
        return
    merit = None
    for clean in config.get(u"cleaners", ()):
        if type(clean) == dict:
            merit = _get_merit(clean[u"merit"], frame)
        else:
            namespace, target = _get_namespace_and_target(clean, frame)
            apply_patch(namespace, target, cleaner(merit))


def sink(merit):
    """Create decorator to turn function into sensitive sink."""

    def inner_sink(func):
        """Turn function f into a sink.

        Make the argument function sensitive for operations with given merit.

        Args:
            f: Function which will be a sink.

        Returns:
            function: A sink sensitive for given merit.

        """

        @wraps(func)
        def inner(*args, **kwargs):
            taint_violations = []
            for arg in args:
                if (isinstance(arg, types.StringTypes) and
                    not arg.isclean(merit)):
                    taint_violations.append(arg)
            for kwarg_value in kwargs.itervalues():
                if (isinstance(kwarg_value, types.StringTypes) and
                    not kwarg_value.isclean(merit)):
                    taint_violations.append(kwarg_value)

            if taint_violations:
                message = ("Following arguments have no merit {}:\n"
                           .format(merit))
                message += "\n".join(taint_violations)
                raise TaintError(message)

            return func(*args, **kwargs)

        return inner

    return inner_sink


def _complex_sink(args_merits, kwargs_merits):
    """Create decorator to turn function into sensitive sink (with different
    taint checks for each argument)."""

    def inner_sink(func):
        """Turn function f into a sink.

        Make the argument function sensitive for operations with merit m.

        Args:
            f: function which will be a sink

        Returns:
            function: a sink sensitive for merit m
        """
        def check(argument, merits):
            if argument is None:
                return
            elif isinstance(argument, types.StringTypes):
                for m in merits:
                    if not argument.isclean(m):
                        raise TaintError("Object \"{}\" has no merit {}."
                                             .format(argument, m))
            elif isinstance(argument, types.DictType):
                for a in argument.itervalues():
                    check(a, merits)
            elif (isinstance(argument, types.ListType) or
                  isinstance(argument, types.TupleType) or
                  isinstance(argument, frozenset) or
                  isinstance(argument, set)):
                for a in argument:
                    check(a, merits)

        @wraps(func)
        def inner(*args, **kwargs):
            for arg, merit in zip(args, args_merits):
                check(arg, merit)

            for kwarg_value in kwargs.keys():
                check(kwargs[kwarg_value], kwargs_merits[kwarg_value])

            return func(*args, **kwargs)

        return inner

    return inner_sink


def _patch_sinks(config, frame):
    """Create all taint sinks specified in config for a given frame."""
    merit = None
    for snk in config.get(u"sinks", ()):
        if type(snk) == dict:
            if u"merit" in snk:
                merit = _get_merit(snk[u"merit"], frame)
                continue
            else:
                for (sink_name, sink_specs) in snk.items():
                    args = _preprocess_complex_args(sink_specs[u"args"],
                                                    frame)
                    kwargs = _preprocess_complex_kwargs(sink_specs[u"kwargs"],
                                                        frame)
                    patch = _complex_sink(args, kwargs)
                    namespace, target = _get_namespace_and_target(sink_name,
                                                                  frame)
        else:
            patch = sink(merit)
            namespace, target = _get_namespace_and_target(snk, frame)
        if not merit:
            raise ValueError(("Malformed config file - expected "
                              "merit, got \"%s\"") % snk)

        apply_patch(namespace, target, patch)


def _patch_propagators(config, frame):
    """Create all taint propagators specified in config for a given frame."""

    for prop in config.get(u"propagators", ()):
        namespace, target = _get_namespace_and_target(prop, frame)
        apply_patch(namespace, target, propagator)


def propagator(obj):
    """ Decorator for turning function or a class into a taint propagator. """

    if isinstance(obj, types.FunctionType):
        return _proxy_function(obj)
    else: # silently assume it's a class
        return _proxy_class(obj)


def apply_patch(namespace, target_name, action):
    """Patch a function or method to give it taint tracking capabilities.

    Args:
        namespace: Namespace in which function/method exists.
        target_name: The name of concerned function/method.
        action: Decorator providing taint tracking capabilities, which will be
            applied to the target.

    Returns:
        None
    """
    target = getattr(namespace, target_name)

    # namespace can either be a class or module, so we will patch either
    # function or method
    if isinstance(namespace, types.TypeType):
        if isinstance(target, types.TypeType):  # a class
            patched = action(target)
        elif isinstance(target, types.FunctionType):
            patched = staticmethod(action(getattr(namespace, target_name)))
        elif target.im_class == type:    # class method
            patched = classmethod(action(target.im_func))
        else:    # instance method
            patched = action(target)
    else:    # regular function
        # namespace is module, so target is a function
        patched = action(target)

    setattr(namespace, target_name, patched)


def _get_namespace_and_target(full_name, frame):
    """Get namespace in which an object exists (and its name relative to that
    namespace) based on its current frame and name relative to current
    namespace.

    Args:
       full_name: Relative name of the object.
       frame: Current frame.

    Returns:
      (namespace, relative_name): tuple such that:
        - namespace: object's namespace
        - relative_name: object's name relative to namespace

    """

    namespace = sys.modules[frame.f_globals["__name__"]]
    traversal = full_name.split(".")
    target = traversal[-1]

    if len(traversal) > 1:
        namespace = getattr(namespace, traversal[0])
    else:
        return namespace, target

    for t in traversal[1:-1]:
        namespace = getattr(namespace, t)

    return namespace, target


def _get_merit(merit_name, frame):
    """Get merit object from given frame by name."""
    namespace, target = _get_namespace_and_target(merit_name, frame)
    return getattr(namespace, target)


def _load_config(config_handle):
    """Load config from file object."""
    return json.load(config_handle)


def _preprocess_check(check_spec, frame):
    """ Extract information about check from check_spec and based on the frame prepare
    list of merits to check against.

    Args:
      check_spec - either a string (when no checks are required) or a
          dictionary with exactly one key being the name of argument, and a
          value being either a merit name, or list of merits names.
      frame - a frame from which merits to check against will be extracted

    Returns:
      a list (perhaps empty) of merit objects to check against

    """
    if type(check_spec) != dict:
        return []  # no checks
    else:
        merits = check_spec.values()[0]
        if type(merits) == list:
            return [_get_merit(m, frame) for m in merits]
        else:
            return [_get_merit(merits, frame)]


def _preprocess_complex_args(sink_args, frame):
    """ Prepare merit checks for each of args of complex sink by extracting
    correct merit from given frame. """
    return [_preprocess_check(a, frame) for a in sink_args]


def _preprocess_complex_kwargs(sink_kwargs, frame):
    """ Prepare merit checks for each of kwargs of complex sink by extracting
    correct merit from given frame.

    Args:
        sink_kwargs - list of merit checks for keyword arguments -
            each item is a merit check specification (as described by
            _preprocess_check)
        frame - a frame from which merits to check against will be extracted

    Returns:
        a dictionary in which keys are names of kwargs, and values are lists
        (perhaps empty) of merit objects to check against
    """

    res = {}
    for k in sink_kwargs:
        checks = _preprocess_check(k, frame)
        name = k if type(k) != dict else k.keys()[0]
        res[name] = checks

    return res


class Validator(object):
    """ Convenience class for validating json configurations. """
    def __init__(self, config):
        self.config = config
        self.supported_fields = [u"sources", u"cleaners", u"sinks", u"options"]
        self.supported_options = [u"propagate_re", u"taint_files"]
        self.errors = []
        self.warnings = []

    def validate(self):
        if not self.validate_fields():
            return self.warnings, self.errors

        self.validate_options()
        self.validate_cleaners()
        self.validate_sinks()

        return self.warnings, self.errors

    def err(self, message):
        self.errors.append(message)

    def warn(self, message):
        self.warnings.append(message)

    def _check_list(self, key, name):
        if key in self.config:
            if not isinstance(self.config[key], types.ListType):
                self.err("Malformed {} in the taint config (expected a"
                         " list, not {})".format(key, type(self.config[key])))

    def _check_merit(self, obj):
        if not isinstance(obj, types.DictType):
            return False
        if not u"merit" in obj.keys():
            return False
        if not isinstance(obj[u"merit"], types.StringTypes):
            return False
        if len(obj) > 1:
            self.err("Malformed merit description {}".format(obj))
        return True

    def _check_patchable(self, obj):
        if not isinstance(obj, types.StringTypes):
            return False
        return re.match("^([_a-zA-Z]\w*)(\.[_a-zA-Z]\w*)*$", obj)

    def _check_complex(self, obj):
        if not isinstance(obj, types.DictType):
            return False
        if len(obj) != 1:
            return False
        specs = obj.values()[0]
        name = obj.keys()[0]

        for x in specs.keys():
            if x not in (u"args", u"kwargs"):
                self.warn("Unexpected key in {}: {}.".format(name, x))

        args, kwargs = [], []
        if u"args" in specs:
            args = specs[u"args"]
            if not isinstance(args, types.ListType):
                self.err("Malformed args (expected list) for complex sink {}."
                         .format(name))
                return False

        if u"kwargs" in specs:
            kwargs = specs[u"kwargs"]
            if not isinstance(kwargs, types.ListType):
                self.err("Malformed kwargs (expected list) for complex sink"
                         " {}.".format(name))
                return False

        for arg in itertools.chain(args, kwargs):
            if (isinstance(arg, types.StringTypes) and
                self._check_identifier(arg)):
                continue
            if not isinstance(arg, types.DictType):
                self.err("Malformed (keyword or positional) argument {}"
                         " in complex sink {}.".format(arg, name))
                return False
            if len(arg) != 1:
                self.err("Malformed (keyword or positional) argument {}"
                         " in complex sink {}.".format(arg, name))
                return False
            merits = arg.values()[0]
            if isinstance(merits, types.ListType):
                if not all([isinstance(m, types.StringTypes) and
                            self._check_identifier(m)
                            for m in merits]):
                    self.err("Malformed merits {} for argument {}"
                             " in complex sink {}.".format(merits,
                                                           arg.keys()[0], name))
                    return False
                continue

            if (isinstance(merits, types.StringTypes) and
                self._check_identifier(merits)):
                continue
            self.err("Malformed merits {} for argument {} in complex sink {}."
                     .format(merits, arg.keys()[0], name))
            return False
        return True

    def _check_identifier(self, identifier):
        return re.match(r'^[_a-zA-Z]\w*$', identifier)

    def validate_fields(self):
        everything = set(self.config.keys())
        expected = set(self.supported_fields)

        if not everything <= expected: # ie. check against unexpected options
            unexpected = sorted(everything - expected)
            self.warn("Unexpected fields in config: {}."
                      .format(", ".join(unexpected)))

        for field in self.supported_fields:
            self._check_list(field, field)

        return not self.errors

    def validate_cleaners(self):
        first_merit = False
        last_merit = None # indicates if previous element of config was a merit
        for c in self.config.get(u"cleaners", ()):
            if self._check_merit(c):
                if last_merit:
                    self.warn("No cleaners specified for merit {}."
                              .format(last_merit))
                else:
                    first_merit = True
                    last_merit = c[u"merit"]
            elif self._check_patchable(c):
                if not first_merit:
                    self.err("No merit specified for cleaner {}.".format(c))
                last_merit = None
            else:
                self.err("Unexpected object in cleaners: {}.".format(c))

        # cleaners should not end with merit
        if last_merit:
            self.warn("No cleaners specified for merit {}.".format(last_merit))

    def validate_options(self):
        if u"options" not in self.config:
            return

        supported_options = set(["propagate_re", "taint_files"])
        unexpected = set(self.config[u"options"]) - set(self.supported_options)

        if unexpected:
            self.warn("Unexpected options: {}"
                      .format(", ".join(sorted(unexpected))))


    def validate_sinks(self):
        last_merit = None
        previous_object = None

        for s in self.config.get(u"sinks", ()):
            if self._check_merit(s):
                if previous_object == "merit":
                    self.warn("No sinks specified for merit {}."
                              .format(last_merit))
                last_merit = s[u"merit"]
                previous_object = "merit"
            elif self._check_patchable(s):
                if not last_merit:
                    self.err("No merit specified for sink {}.".format(s))
                elif previous_object == "complex":
                    self.warn("Config may be confusing - simple sink {} is"
                              " preceded by a complex sink, not simple sink or"
                              " merit.".format(s))
                previous_object = "patchable"
            elif self._check_complex(s):
                if previous_object == "merit" and last_merit:
                    self.warn("Config may be confusing - complex sink {}"
                              " preceded by a merit {}, not another sink."
                              .format(s.keys()[0], last_merit))
                previous_object = "complex"
            else:
                self.err("Unexpected object in sinks: {}.".format(s))

        if last_merit:
            self.warn("No sinks specified for merit {}.".format(last_merit))


def _apply_options(config, current_frame):
    """ Apply global taint options to the application. Currently supported
    options are:
      - propagate_re - add taint propagation to regular expressions
      - taint_files - make fileobjects returned by open tainted
    """

    for option in config.get(u"options", ()):
        if option == u"propagate_re":
            _patch_re()
        elif option == u"taint_files":
            _patch_file_handles()


def _patch_re():
    """ Patch regular expressions for taint propagation. Taint will be
    propagated from arguments of re modules functions, like re.search into both
    compiled re objects and re matches. """

    import sre_compile, re

    propagators = [
          "match",
          "search",
          "sub",
          "subn",
          "split",
          "findall",
          "finditer",
          "escape",
          "compile"
        ]

    for p in propagators:
        setattr(re, p, _proxy_function(getattr(re, p)))

    # patch compilation to make caching taint aware
    def _compile(*key):
        # internal: compile pattern
        taint = _get_taint(key[0])
        if taint is not None: # can't hash the set
            taint = tuple(taint)
        cachekey = (type(key[0]), key, taint)
        p = re._cache.get(cachekey)
        if p is not None:
            return p
        pattern, flags = key
        if isinstance(pattern, re._pattern_type):
            if flags:
                raise ValueError("Cannot process flags argument with"
                                 " a compiled pattern")
            return pattern
        if not sre_compile.isstring(pattern):
            raise TypeError("first argument must be string or compiled"
                            " pattern")

        p = sre_compile.compile(pattern, flags)

        if len(re._cache) >= re._MAXCACHE:
            re._cache.clear()
        re._cache[cachekey] = p
        return p

    setattr(re, "_compile", _compile)


def _patch_file_handles():
    """ Proxy fileobjects for taint propagation. Every fileobject created by
    open will return tainted contents. """
    globals()["open"] = _proxy_function(open, tainted=True)


def enable(config_name="PLUMBING"):
    """Enable taint tracking in module.

    Monkey patches everything given in config file.

    Args:
        config_name: Name of the config file.
    """

    with open(config_name) as config_handle:
        config = _load_config(config_handle)

    current_frame = getouterframes(currentframe())[1][0]

    _apply_options(config, current_frame)
    _patch_sources(config, current_frame)
    _patch_sinks(config, current_frame)
    _patch_cleaners(config, current_frame)
    _patch_propagators(config, current_frame)


# Context managers.
# Disable pylint warning: "undefined variable: Merit" (it is a new builtin,
# pylint is not aware of it yet):
# pylint: disable=E0602 class _PropagationContext(object):

@contextmanager
def unsafePropagationFull(merit):
    propagation = merit.propagation
    merit.propagation = Merit.FullPropagation
    yield
    merit.propagation = propagation

@contextmanager
def unsafePropagationPartial(merit):
    propagation = merit.propagation
    merit.propagation = Merit.PartialPropagation
    yield
    merit.propagation = propagation

@contextmanager
def unsafePropagationNone(merit):
    propagation = merit.propagation
    merit.propagation = Merit.NonePropagation
    yield
    merit.propagation = propagation


# TODO(marcinf) some merits (choose propagation for them)
class SecretMerit(Merit): pass
class PickleMerit(Merit): pass
class ShellMerit(Merit): pass
class XSSMerit(Merit): pass
class SQLiMerit(Merit): pass


class Taintable(object):
    """ Base class for taint propagator proxies. """

    # special cases
    def __iter__(self):
        obj = object.__getattribute__(self, "__obj")
        return _taint_attr(object.__getattribute__(obj, "__iter__"),
                           object.__getattribute__(self, "__taint"))()

    def next(self):
        obj = object.__getattribute__(self, "__obj")
        return _taint_attr(object.__getattribute__(obj, "next"),
                           object.__getattribute__(self, "__taint"))()

    def __str__(self):
        return str(object.__getattribute__(self, "__obj"))

    def __repr__(self):
        return repr(object.__getattribute__(self, "__obj"))

    def __unicode__(self):
        return unicode(object.__getattribute__(self, "__obj"))

    def __nonzero__(self):
        return bool(object.__getattribute__(self, "__obj"))

    # attributes
    def __getattribute__(self, attr):
        return _taint_attr(getattr(object.__getattribute__(self, "__obj"),
                                  attr),
                           object.__getattribute__(self, "__taint"))

    # TODO it is also possible to propagate taint when setting
    # perhaps an object which taint is modified by setting attributes may be a
    # good idea in future.

    def __setattr__(self, attr, value):
        setattr(object.__getattribute__(self, "__obj"), attr, value)

    def __delattr__(self, attr):
        delattr(object.__getattribute__(self, "__obj"), attr)

# magic methods to create for taint proxies
_magic_methods = ["__lt__", "__le__", "__eq__", "__ne__", "__gt__", "__ge__",
                  "__cmp__", "__rcmp__", "__hash__", "__get__",
                  "__set__", "__delete__", "__isinstancecheck__",
                  "__subclasshook__", "__call__", "__len__", "__getitem__",
                  "__setitem__", "__delitem__", "__reversed__",
                  "__contains__", "__getslice__", "__setslice__",
                  "__delslice__", "__add__", "__sub__", "__mul__",
                  "__floordiv__", "__mod__", "__divmod__", "__pow__",
                  "__lshift__", "__rshift__", "__and__", "__xor__", "__or__",
                  "__div__", "__truediv__", "__radd__", "__rsub__",
                  "__rmul__", "__rdiv__", "__rtruediv__", "__rfloordiv__",
                  "__rmod__", "__rdivmod__", "__rpow__", "__rlshift__",
                  "__rrshift__", "__rand__", "__rxor__", "__ror__",
                  "__iadd__", "__isub__", "__imul__", "__idiv__",
                  "__itruediv__"]


def _proxy_class(kls):
    """ Create a proxy class for kls which propagates taint, but otherwise
    behaves the same. """

    class MC(type):
        """ Metaclass for the taint propagating proxy. """
        def __repr__(self):
            return repr(kls) + " (tainted)"

        def __str__(self):
            return str(kls) + " (tainted)"

        def __unicode__(self):
            return unicode(kls) + " (tainted)"

        def __new__(mcs, name, bases, dct):
            for m in _magic_methods:
                if hasattr(kls, m):
                    def _tainted_meth(self, *arg, **kwargs):
                        taint = _collect_taint(list(args) + kwargs.values() +
                                     [object.__getattribute__(obj, "__taint")])
                        return _taint_object(getattr(kls, m), taint)
                    dct[m] = getattr(kls, m)
            return type.__new__(mcs, "%s" % kls.__name__, bases, dct)

    class Propagator(Taintable):
        __metaclass__ = MC

        def __init__(self, *args, **kwargs):
            object.__setattr__(self, "__obj", kls(*args, **kwargs))
            object.__setattr__(self, "__cls", kls)
            taint = _collect_taint(list(args) + kwargs.values())
            object.__setattr__(self, "__taint", taint)


    return Propagator

class Propagator(Taintable):
    def __new__(cls, obj, taint):
        dct = {}
        for m in _magic_methods:
            if hasattr(cls, m):
                def _tainted_meth(self, *arg, **kwargs):
                    taint = _collect_taint(list(args) + kwargs.values() +
                                 [object.__getattribute__(obj, "__taint")])
                    return _taint_object(getattr(kls, m), taint)

        cls_tainted = type("%s" % cls.__name__, cls.__mro__, dct)
        return object.__new__(cls_tainted)

    def __init__(self, obj, taint):
        object.__setattr__(self, "__obj", obj)
        object.__setattr__(self, "__taint", taint)


def _propagator_wrapper(obj, taint):
    """ Default wrapper for propagating taint over arbitrary object. For objects
    of types: NoneType, int, float, bool, long, the same object is returned. For
    objects of other types, given object is wrapped in the Propagator. """
    if type(obj) in [types.NoneType, types.IntType, types.FloatType,
                     types.BooleanType, types.LongType]:
        return obj
    else:
        return Propagator(obj, taint)


def _proxy_function(func, tainted=False):
    """ Decorate a function func so that it will return a tainted object.
    Type of decorated function return value depends on func's return value. If
    it is a:
      - string/unicode - they will be tainted by their builtin mechanisms
      - builtin collection of taintable objects - each object of collection
        will be tainted (for dictionaries, only values are tainted, keys are not
        modified)
      - other object - it will proxied by Propagator class

    The taint value will be either:
      - when tainted is false (default) - result of taint propagation between
        func's arguments
      - when tainted is true - always tainted with no merits
      """

    @wraps(func)
    def inner(*args, **kwargs):
        taint = _collect_taint(list(args) + kwargs.values())
        if tainted:
            taint = _propagate(taint, tuple())
        res = func(*args, **kwargs)

        return _taint_object(res, taint)

    return inner


# Taint utilities
#
#
# TODO similar utilities are provided by taintobject.c . Probably a Python
# wrapper around it would be better idea than redefining them again here.

def _get_taint(obj):
    """ Extract taint from taintable object - either string/unicode with builtin
    taint or an object proxied inside taint propagator. """
    if isinstance(obj, types.StringTypes):
        return obj._merits()
    elif isinstance(obj, Taintable):
        return object.__getattribute__(obj, "__taint")
    return None


def _collect_taint(objects):
    """ Return result of taint propagation across objects from given list. """
    if not objects:
        return None

    taint = _get_taint(objects[0])
    for o in objects[1:]:
        taint = _propagate(taint, _get_taint(o))
    return taint

def _propagate(a, b):
    """ Using taint propagation semantics, propagate merits between a and b.
    Both a and b represent taint, being either a collection of merits (perhaps
    empty) or None (when representing "taint" of untainted object)."""


    # both clean
    if a is None and b is None:
        return None

    # both tainted
    if a is not None and b is not None:
        return set(merit for merit in set(a) & set(b)
                   if merit.propagation != Merit.NonePropagation)

    # one is tainted, other clean
    if a is None:
        source = b
    else:
        source = a
    source = set(source)

    return set(merit for merit in source
               if merit.propagation == Merit.FullPropagation)

def _taint_object(obj, taint=(), taint_wrapper=_propagator_wrapper):
    """ Taint arbitrary object with the taint. For string/unicode objects, their
    builtin taint mechanisms will be used. For builtin collections, each item
    will be tainted recursively with this function (for dicts, only values are
    tainted). For other objects, taint_wrapper will be used to give them taint
    propagating capabilities (default taint_wrapper is the Propagator proxy
    class).

    Args:
      - obj - object to taint
      - taint - None (when object should actually remain clean) or collection of
        merits (perhaps empty, if the object should be tainted with no merits)
        defaults to empty tuple
      - taint_wrapper - a callable to wrap untaintable objects with taint
        propagation - defaults to Propagator

    """

    if isinstance(obj, types.StringTypes):
        if taint is None:
            return obj
        obj = obj.taint()
        for merit in taint:
            obj = obj._cleanfor(merit)
        return obj
    elif type(obj) is types.ListType:
        return [_taint_object(o, taint) for o in obj]
    elif type(obj) is types.TupleType:
        return tuple(_taint_object(o, taint) for o in obj)
    elif type(obj) is types.DictType:
        return {k: _taint_object(v, taint) for (k, v) in obj.iteritems()}
    elif type(obj) is set:
        return set(_taint_object(o, taint) for o in obj)
    elif type(obj) is frozenset:
        return frozenset(_taint_object(o, taint) for o in obj)
    else:
        return taint_wrapper(obj, taint)

def _taint_attr(attr, taint):
    if callable(attr):
        def f(*args, **kwargs):
            res = attr(*args, **kwargs)
            new_taint = _collect_taint(list(args) + kwargs.values())
            new_taint = _propagate(new_taint, taint)
            return _taint_object(res, new_taint)
        return f
    else:
        return _taint_object(attr, taint)


