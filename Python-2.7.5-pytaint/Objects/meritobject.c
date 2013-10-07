#define PY_SSIZE_T_CLEAN

#include <Python.h>

typedef struct {
    PyObject_HEAD
} PyMeritObject;

static void
Merit_dealloc(PyObject* self)
{
    Py_TYPE(self)->tp_free(self);
}


PyTypeObject PyMerit_MeritType = {
    PyObject_HEAD_INIT(NULL)
    0,                                          /* ob_size */
    "taint.Merit",                              /* tp_name */
    sizeof(PyMeritObject),                      /* tp_basicsize */
    0,                                          /* tp_itemsize */
    (destructor)Merit_dealloc,                  /* tp_dealloc */
    0,                                          /* tp_print */
    0,                                          /* tp_getattr */
    0,                                          /* tp_setattr */
    0,                                          /* tp_compare */
    0,                                          /* tp_repr */
    0,                                          /* tp_as_number */
    0,                                          /* tp_as_sequence */
    0,                                          /* tp_as_mapping */
    0,                                          /* tp_hash */
    0,                                          /* tp_call */
    0,                                          /* tp_str */
    0,                                          /* tp_getattro */
    0,                                          /* tp_setattro */
    0,                                          /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,   /* tp_flags */
    "Merit object",                             /* tp_doc */
    0,                                          /* tp_traverse */
    0,                                          /* tp_clear */
    0,                                          /* tp_richcompare */
    0,                                          /* tp_weaklistoffset */
    0,                                          /* tp_iter */
    0,                                          /* tp_iternext */
    0,                                          /* tp_methods */
    0,                                          /* tp_members */
    0,                                          /* tp_getset */
    &PyBaseObject_Type,                         /* tp_base */
    0,                                          /* tp_dict */
    0,                                          /* tp_descr_get */
    0,                                          /* tp_descr_set */
    0,                                          /* tp_dictoffset */
    0,                                          /* tp_init */
    0,                                          /* tp_alloc */
    0,                                          /* tp_new */
    0,                                          /* tp_free */
};

typedef struct {
    PyObject_HEAD
    char ob_strat;
} PyPropagationObject;

static void
Propagation_dealloc(PyObject* self)
{
    Py_TYPE(self)->tp_free(self);
}

static char *propagation_names[3] = {
    "Full",
    "None",
    "Partial"
};

#define PROPAGATION_NAMES_SIZE \
    (sizeof(propagation_names)/sizeof(*propagation_names))

PyObject *
Propagation_repr(PyObject* self) {
    int s = (int)((PyPropagationObject*)self)->ob_strat;
    if (s >= 0 && s < PROPAGATION_NAMES_SIZE)
        return PyString_FromFormat("<taint.Merit.%sPropagation>",
                                   propagation_names[s]);

    // TODO(marcinf) what should happen here - exception or exit?
    return NULL;
}

PyObject *
Propagation_str(PyObject* self) {
    int s = (int)((PyPropagationObject*)self)->ob_strat;
    if (s >= 0 && s < PROPAGATION_NAMES_SIZE)
        return PyString_FromFormat("<%sPropagation>",
                                   propagation_names[s]);

    // TODO(marcinf) what should happen here - exception or exit?
    return NULL;
}


PyTypeObject PyMerit_PropagationType = {
    PyObject_HEAD_INIT(NULL)
    0,                                          /* ob_size */
    "taint.Propagation",                        /* tp_name */
    sizeof(PyPropagationObject),                /* tp_basicsize */
    0,                                          /* tp_itemsize */
    (destructor)Propagation_dealloc,            /* tp_dealloc */
    0,                                          /* tp_print */
    0,                                          /* tp_getattr */
    0,                                          /* tp_setattr */
    0,                                          /* tp_compare */
    Propagation_repr,                           /* tp_repr */
    0,                                          /* tp_as_number */
    0,                                          /* tp_as_sequence */
    0,                                          /* tp_as_mapping */
    0,                                          /* tp_hash */
    0,                                          /* tp_call */
    Propagation_str,                            /* tp_str */
    0,                                          /* tp_getattro */
    0,                                          /* tp_setattro */
    0,                                          /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,   /* tp_flags */
    "Propagation object",                       /* tp_doc */
    0,                                          /* tp_traverse */
    0,                                          /* tp_clear */
    0,                                          /* tp_richcompare */
    0,                                          /* tp_weaklistoffset */
    0,                                          /* tp_iter */
    0,                                          /* tp_iternext */
    0,                                          /* tp_methods */
    0,                                          /* tp_members */
    0,                                          /* tp_getset */
    &PyBaseObject_Type,                         /* tp_base */
    0,                                          /* tp_dict */
    0,                                          /* tp_descr_get */
    0,                                          /* tp_descr_set */
    0,                                          /* tp_dictoffset */
    0,                                          /* tp_init */
    0,                                          /* tp_alloc */
    0,                                          /* tp_new */
    0,                                          /* tp_free */
};

PyObject *_PyMerit_FullPropagation;
PyObject *_PyMerit_PartialPropagation;
PyObject *_PyMerit_NonePropagation;

void
_PyTaint_Init(void)
{
    PyMerit_MeritType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&PyMerit_MeritType) < 0) {
        return;
    }

    PyMerit_PropagationType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&PyMerit_PropagationType) < 0) {
        return;
    }

    _PyMerit_FullPropagation = (PyObject*)PyObject_New(PyPropagationObject,
                                                  &PyMerit_PropagationType);
    ((PyPropagationObject*)_PyMerit_FullPropagation)->ob_strat = 0;
    _PyMerit_NonePropagation = (PyObject*)PyObject_New(PyPropagationObject,
                                                  &PyMerit_PropagationType);
    ((PyPropagationObject*)_PyMerit_NonePropagation)->ob_strat = 1;
    _PyMerit_PartialPropagation = (PyObject*)PyObject_New(PyPropagationObject,
                                                  &PyMerit_PropagationType);
    ((PyPropagationObject*)_PyMerit_PartialPropagation)->ob_strat = 2;

    PyDict_SetItemString(PyMerit_MeritType.tp_dict, "FullPropagation",
                         _PyMerit_FullPropagation);
    PyDict_SetItemString(PyMerit_MeritType.tp_dict, "PartialPropagation",
                         _PyMerit_PartialPropagation);
    PyDict_SetItemString(PyMerit_MeritType.tp_dict, "NonePropagation",
                         _PyMerit_NonePropagation);
    PyDict_SetItemString(PyMerit_MeritType.tp_dict, "propagation",
                         _PyMerit_NonePropagation);
}
