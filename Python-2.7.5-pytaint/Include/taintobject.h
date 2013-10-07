#ifndef Py_TAINTOBJECT_H
#define Py_TAINTOBJECT_H
#ifdef __cplusplus
extern "C" {
#endif

typedef struct { PyObject_VAR_HEAD } PyTaintObject;

/*  Create an object representing taint with no merits (ie. empty tuple).
    Returns NULL on failure.
*/

PyAPI_FUNC(PyTaintObject*) PyTaint_EmptyMerits();

/*  Return a new taint object having all the merits of old one and also
    new_merit. Returns NULL on failure.
*/

PyAPI_FUNC(PyTaintObject*) _PyTaint_AddMerit(PyTaintObject *taint,
                                             PyObject *new_merit);

/* Extract taint from taintable object - ie. string or unicode. Since it should
   be only used internally, Py_FatalError is raised when an invalid object is
   passed. Returns borrowed reference.
 */
PyTaintObject*
_PyTaint_GetFromObject(PyObject *obj);

/* Checks if object is a valid merit object with a valid propagation strategy.

   Returns -1 on failure, 1 on success. */
int
_PyTaint_ValidMerit(PyObject *obj);

/* Apply taint propagation rules to a and b and store result in r.

   Returns -1 on failure, 1 on success. */
PyAPI_FUNC(int) PyTaint_PropagationResult(
    PyTaintObject **r,
    PyTaintObject *a,
    PyTaintObject *b
    );

/* Apply taint propagation rules to target and source and store result in
   target. This function creates a new PyTaintObject instead of modifying
   old one.

   Returns -1 on failure, 1 on success. The reference to original target is
   stolen; a new object is created and its ownership is transferred to the
   caller. */
int
PyTaint_PropagateTo(PyTaintObject **target,
                    PyTaintObject *source);

/* For taintable object obj, return object with the same contents as obj and
   passed taint value. Steals reference to obj when succesful.

   Returns NULL on failure. If obj is not taintable (ie. not a unicode nor
   string), a TypeError is raised.
 */
PyAPI_FUNC(PyObject*)
PyTaint_AssignToObject(PyObject *obj, PyTaintObject *taint);

/* Returns 1 if given object is taintable, 0 otherwise. Recognized taintable
   objects are stringobject and unicode.
 */
PyAPI_FUNC(int)
PyTaint_IsTaintable(PyObject *obj);

/* --- Macros -------------------------------------------------------------- */
#define PyTaint_IS_CLEAN(x) (((PyTaintObject*)x == NULL))

/* --- Collection tainting ------------------------------------------------- */

/* Assign source taint object to each element in target list, modifying them.
   It is assumed that all elements of the list are stringobjects with NULL
   ob_merits. In case any of the elements is shared (interned or have a refcount
   bigger than one), it is replaced with a new copy of itself.

   This function doesn't check validity of its arguments.

   Returns 1 on success, -1 on failure (ie. when it failed when attempting to
   copy one of its items).
*/
PyAPI_FUNC(int) _PyTaint_TaintStringListItems(
    PyObject *target,
    PyTaintObject *source
    );

/* Create a copy of tuple target in which every element's taint is a copy of
   source. It is assumed that target is a tuple of non tainted string objects.
   In case any of the strings is shared (interned or have a refcount bigger
   than one), a new copy of the string is created (otherwise, an inplace
   tainting is done).

   This function steals reference to target and doesn't check validity of its
   arguments.

   Returns tuple with tainted items on success, NULL on failure (ie. when it
   failed when attempting to create a new tuple/string).
*/
PyAPI_FUNC(PyObject*) _PyTaint_TaintStringTupleItems(
    PyObject *target,
    PyTaintObject *source
    );

/* Works the same as _PyTaint_TaintStringTupleItems, except that assumes that
   elements of the tuple are unicode objects. */

PyAPI_FUNC(PyObject*) _PyTaint_TaintUnicodeTupleItems(
    PyObject *target,
    PyTaintObject *source
    );

/* Works the same as _PyTaint_TaintStringListItems, except that assumes that
   elements of the list are unicode objects. */
PyAPI_FUNC(int) _PyTaint_TaintUnicodeListItems(
    PyObject *target,
    PyTaintObject *source
    );

#ifdef __cplusplus
}
#endif
#endif /* !Py_STRINGOBJECT_H */
