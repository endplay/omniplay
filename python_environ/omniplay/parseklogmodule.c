#include <Python.h>
#include <structmember.h>

#include "parseklib.h"

/* Okay, declare klog structure here? */
/* We're just going to make the log iterable */

/* And the klog_entry structure */
/* For now, just duplicate the data in the python structure... */

typedef struct {
	PyObject_HEAD
	PyObject *filename;
	struct klogfile *log;
} Parseklog;

typedef struct {
	PyObject_HEAD
	PyObject *klog;
	struct klog_result *raw;

	loff_t index;

	PyObject *retparams;

	u_long start_clock;
	u_long stop_clock;

	long retval;
	
	PyObject *signal;
} ParseklogEntry;

typedef struct {
	PyObject_HEAD
	int number;
	PyObject *next;
} ParseklogSignal;

static PyObject *ParseklogSignal_new(PyTypeObject *type, PyObject *args,
	 	PyObject *kwds) {
	ParseklogSignal *self;

	self = (ParseklogSignal *)type->tp_alloc(type, 0);
	if (self == NULL) {
		goto out;
	}

	self->number = -1;
	self->next = NULL;

out:
	return (PyObject *)self;
}

static int ParseklogSignal_init(ParseklogEntry *self, PyObject *args, PyObject *kwds) {
	PyObject *next;
	PyObject *tmp;

	static char *kwlist[] = {"number", "next", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|iO", kwlist, &self->number, &next)) {
		return -1;
	}

	if (!log) {
		return -1;
	}

	tmp = self->next;
	Py_INCREF(next);
	self->next = next;
	if (tmp) {
		Py_DECREF(tmp);
	}

	return 0;
}

static void ParseklogEntry_dealloc(ParseklogEntry *self) {
	Py_XDECREF(self->next);

	self->ob_type->tp_free((PyObject *)self);
}

static PyMemberDef ParseklogSignal_members[] = {
	{"number", T_INT, offsetof(ParseklogSignal, number)},
	{"next", T_OBJECT_EX, offsetof(ParseklogSignal, next)},
	{NULL}
};

static PyMethodDef ParseklogSignal_methods[] = {
	{NULL}
};

static PyTypeObject ParseklogSignalType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "parseklog.ParseklogSignalRaw",             /*tp_name*/
    sizeof(ParseklogSignal),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)ParseklogSignal_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    "Parseklog signal object (wrapper for parseklib.h)",           /* tp_doc */
    0,		               /* tp_traverse */
    0,		               /* tp_clear */
    0,		               /* tp_richcompare */
    0,		               /* tp_weaklistoffset */
    0,		               /* tp_iter */
    0,		               /* tp_iternext */
    ParseklogSignal_methods,             /* tp_methods */
    ParseklogSignal_members,             /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)ParseklogSignal_init,      /* tp_init */
    0,                         /* tp_alloc */
    ParseklogSignal_new,                 /* tp_new */
};

static PyObject *ParseklogEntry_new(PyTypeObject *type, PyObject *args,
	 	PyObject *kwds) {
	ParseklogEntry *self;

	self = (ParseklogEntry *)type->tp_alloc(type, 0);
	if (self == NULL) {
		goto out;
	}

	self->klog = NULL;
	self->raw = NULL;

out:
	return (PyObject *)self;
}

static int ParseklogEntry_init(ParseklogEntry *self, PyObject *args, PyObject *kwds) {
	PyObject *log;
	PyObject *tmp;

	static char *kwlist[] = {"log", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|O", kwlist, &log)) {
		return -1;
	}

	if (!log) {
		return -1;
	}

	tmp = self->klog;
	Py_INCREF(log);
	self->klog = log;
	if (tmp) {
		Py_DECREF(tmp);
	}

	self->raw = NULL;

	return 0;
}

static void ParseklogEntry_dealloc(ParseklogEntry *self) {
	Py_XDECREF(self->klog);

	self->ob_type->tp_free((PyObject *)self);
}

static PyMemberDef ParseklogEntry_members[] = {
	{"klog", T_OBJECT_EX, offsetof(ParseklogEntry, klog)},
	{"index", T_LONGLONG, offsetof(ParseklogEntry, index)},
	{"retparams", T_OBJECT_EX, offsetof(ParseklogEntry, retparams)},
	{"start_clock", T_ULONG, offsetof(ParseklogEntry, start_clock)},
	{"stop_clock", T_ULONG, offsetof(ParseklogEntry, stop_clock)},
	{"retval", T_LONG, offsetof(ParseklogEntry, retval)},
	{"signal", T_OBJECT_EX, offsetof(ParseklogEntry, signal)},
	{NULL}
};

static PyMethodDef ParseklogEntry_methods[] = {
	{NULL}
};

static PyTypeObject ParseklogEntryType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "parseklog.ParseklogEntryRaw",             /*tp_name*/
    sizeof(ParseklogEntry),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)ParseklogEntry_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    "Parseklog log object (wrapper for parseklib.h)",           /* tp_doc */
    0,		               /* tp_traverse */
    0,		               /* tp_clear */
    0,		               /* tp_richcompare */
    0,		               /* tp_weaklistoffset */
    0,		               /* tp_iter */
    0,		               /* tp_iternext */
    ParseklogEntry_methods,             /* tp_methods */
    ParseklogEntry_members,             /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)ParseklogEntry_init,      /* tp_init */
    0,                         /* tp_alloc */
    ParseklogEntry_new,                 /* tp_new */
};

static PyObject *Parseklog_new(PyTypeObject *type, PyObject *args,
	 	PyObject *kwds) {
	Parseklog *self;

	self = (Parseklog *)type->tp_alloc(type, 0);
	if (self == NULL) {
		goto out;
	}

	self->filename = PyString_FromString("");
	if (self->filename == NULL) {
		Py_DECREF(self);
	}
	self->log = NULL;

out:
	return (PyObject *)self;
}

static int Parseklog_init(Parseklog *self, PyObject *args, PyObject *kwds) {
	PyObject *pyfilename;
	PyObject *tmp;

	const char *filename;

	static char *kwlist[] = {"filename", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|O", kwlist, &pyfilename)) {
		return -1;
	}

	if (!pyfilename) {
		return -1;
	}

	tmp = self->filename;
	Py_INCREF(pyfilename);
	self->filename = pyfilename;
	if (tmp) {
		Py_DECREF(tmp);
	}

	filename = PyString_AsString(pyfilename);

	self->log = parseklog_open(filename);

	return 0;
}

static void Parseklog_dealloc(Parseklog *self) {
	Py_XDECREF(self->filename);
	if (self->log != NULL) {
		parseklog_close(self->log);
	}

	self->ob_type->tp_free((PyObject *)self);
}

static PyObject *retpsig_to_pysig(struct klog_signal *sig) {
	ParseklogSignal *base_signal = NULL;
	struct klog_signal *cur_sig = sig;
	struct klog_signal *next_sig;

	if (sig) {
		ParseklogSignal *cur_signal;
		base_signal = (ParseklogSignal *)PyObject_CallObject((PyObject *)&ParseklogSignalType, NULL);

		base_signal->next = NULL;
		base_signal->number = sig->sig.signr;

		cur_signal = base_signal;

		while (cur_sig) {
			Parseklog_signal *next_signal;
			next_sig = sig->next;

			next_signal = NULL;
			if (next_sig) {
				next_signal = (ParseklogSignal *)PyObject_CallObject((PyObject *)&ParseklogSignalType, NULL);
			}
			cur_signal->next = next_signal;
			cur_signal->number = cur_sig->sig.signr;

			cur_signal = next_signal;
			cur_sig = next_sig;
		}
	}

	return (PyObject *)base_signal;
}

static void populate_entry(ParseklogEntry *entry) {
	struct klog_result *res = entry->raw;

	assert(res);

	entry->index = res->index;
	entry->start_clock = res->start_clock;
	entry->stop_clock = res->stop_clock;
	entry->retval = res->retval;

	entry->retvals = NULL;
	if (res->retparams) {
		entry->retparams = PyByteArray_FromStringAndSize(res->retparams,
				res->retparams_size);
		assert(res->retparams_size == PyByteArray_Size(entry->retparams));
	}

	entry->signal = repsig_to_pysig(res->signal);
}

static PyObject *Parseklog_get_next_psr(Parseklog *self, PyObject *args) {
	struct klog_result *res = NULL;
	PyObject *entry = NULL;
	PyObject *arglist = NULL;
	ParseklogEntry *entryraw;

	res = parseklog_get_next_psr(self->log);

	if (!res) {
		goto out;
	}

	arglist = PyBuildValue("O", self);

	entry = PyObject_CallObject((PyObject *)&ParseklogEntryType, arglist);

	entryraw = (ParseklogEntry *)entry;

	entryraw->raw = res;

	populate_entry(entryraw);

	Py_XDECREF(arglist);

out:
	return entry;
}

static PyObject *Parseklog_get_next_psr(Parseklog *self, PyObject *args) {
}

static PyObject *Parseklog_get_next_psr(Parseklog *self, PyObject *args) {
}

static PyMemberDef Parseklog_members[] = {
	{"filename", T_OBJECT_EX, offsetof(Parseklog, filename)},
	{NULL}
};

static PyMethodDef Parseklog_methods[] = {
	{"get_next_psr", (PyCFunction)Parseklog_get_next_psr, METH_NOARGS,
		"Returns the next psr from the log"},
	{"read_next_chunk", (PyCFunction)Parseklog_read_next_chunk, METH_NOARGS,
		"Reads the next chunk from the log into ram"},
	{"cur_chunk_size", (PyCFunction)Parseklog_cur_chunk_size, METH_NOARGS,
		"Gets the number of entries in the current chunk"},
	{"write_chunk", (PyCFunction)Parseklog_write_chunk, METH_VARARGS,
		"Writes the current chunk out to the passed in fd"},
	{NULL}
};

static PyTypeObject ParseklogType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "parseklog.ParseklogRaw",             /*tp_name*/
    sizeof(Parseklog),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)Parseklog_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    "Parseklog log object (wrapper for parseklib.h)",           /* tp_doc */
    0,		               /* tp_traverse */
    0,		               /* tp_clear */
    0,		               /* tp_richcompare */
    0,		               /* tp_weaklistoffset */
    0,		               /* tp_iter */
    0,		               /* tp_iternext */
    Parseklog_methods,             /* tp_methods */
    Parseklog_members,             /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)Parseklog_init,      /* tp_init */
    0,                         /* tp_alloc */
    Parseklog_new,                 /* tp_new */
};

static PyMethodDef module_methods[] = {
	{NULL}
};

#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
initparseklog(void) {
	PyObject *m;

	if (PyType_Ready(&ParseklogType) < 0) {
		return;
	}

	if (PyType_Ready(&ParseklogEntryType) < 0) {
		return;
	}

	m = Py_InitModule3("parseklog", module_methods,
			"Module to facilitate klog parsing from python");

	if (m == NULL) {
		return;
	}

	Py_INCREF(&ParseklogType);
	Py_INCREF(&ParseklogEntryType);
	PyModule_AddObject(m, "ParseklogRaw", (PyObject *)&ParseklogType);
	PyModule_AddObject(m, "ParseklogEntryRaw", (PyObject *)&ParseklogEntryType);
}

/*
int main(int argc, char *argv[]) {
	Py_SetProgramName(argv[0]);

	Py_Initialize();
}
*/

