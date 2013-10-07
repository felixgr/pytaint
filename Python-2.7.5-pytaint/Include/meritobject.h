#ifndef Py_MERITOBJECT_H
#define Py_MERITOBJECT_H
#ifdef __cplusplus
extern "C" {
#endif


PyAPI_DATA(PyTypeObject) PyMerit_MeritType;
PyAPI_DATA(PyObject*) _PyMerit_FullPropagation;
PyAPI_DATA(PyObject*) _PyMerit_PartialPropagation;
PyAPI_DATA(PyObject*) _PyMerit_NonePropagation;

#define PyMerit_FULL_PROPAGATION(m) ( \
         PyObject_GetAttrString(m, "propagation") == \
         (PyObject *)_PyMerit_FullPropagation)
#define PyMerit_PARTIAL_PROPAGATION(m) ( \
         PyObject_GetAttrString(m, "propagation") == \
         (PyObject *)_PyMerit_PartialPropagation)
#define PyMerit_NONE_PROPAGATION(m) ( \
         PyObject_GetAttrString(m, "propagation") == \
         (PyObject *)_PyMerit_NonePropagation)

PyAPI_FUNC(void) _PyTaint_Init(void);

#ifdef __cplusplus
}
#endif
#endif /* !Py_MERITOBJECT_H */
