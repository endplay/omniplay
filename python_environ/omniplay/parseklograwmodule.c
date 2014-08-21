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

	int sysnum;
	int flags;
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
	char raw[172];
} ParseklogSignal;

static PyObject *ParseklogSignal_new(PyTypeObject *type, PyObject *args,
	 	PyObject *kwds) {
	ParseklogSignal *self;

	self = (ParseklogSignal *)type->tp_alloc(type, 0);
	if (self == NULL) {
		goto out;
	}

	self->number = -1;
	self->next = Py_None;;

out:
	return (PyObject *)self;
}

static int ParseklogSignal_init(ParseklogSignal *self, PyObject *args, PyObject *kwds) {
	PyObject *next = NULL;
	PyObject *tmp;

	static char *kwlist[] = {"number", "next", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|iO", kwlist, &self->number, &next)) {
		return -1;
	}

	tmp = self->next;
	if (next) {
		Py_INCREF(next);
	}
	self->next = next;
	if (tmp) {
		Py_DECREF(tmp);
	}

	return 0;
}

static void ParseklogSignal_dealloc(ParseklogSignal *self) {
	Py_XDECREF(self->next);

	self->ob_type->tp_free((PyObject *)self);
}

static PyObject *ParseklogSignal_str(ParseklogSignal *str) {
	return PyString_FromFormat("ParseklogSignal[number: %d, next: %s])",
			str->number, PyString_AsString(PyObject_Str(str->next)));
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
    "parseklog.ParseklogSignal",             /*tp_name*/
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
    (reprfunc)ParseklogSignal_str,       /*tp_str*/
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

	self->sysnum = 0;
	self->flags = 0;
	self->index = -1;

	self->retparams = Py_None;

	self->start_clock = 0;
	self->stop_clock = 0;

	self->retval = 0;
	
	self->signal = Py_None;

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

static PyObject *ParseklogEntry_str(ParseklogEntry *str) {
	/*
	return PyString_FromFormat("ParseklogEntryRaw(index %lld, sysnum %d, "
			"start_clock %lu, stop_clock %lu, retval %ld, signal %s)",
		str->index, str->sysnum, str->start_clock, str->stop_clock,
		str->retval, PyString_AsString(PyObject_Str(str->signal)));
		*/
	return PyString_FromFormat("ParseklogEntryRaw(index %lld, sysnum %d, "
			"start_clock %lu, stop_clock %lu, retval %ld, signal %p)",
		str->index, str->sysnum, str->start_clock, str->stop_clock,
		str->retval, str->signal);
}

static void ParseklogEntry_dealloc(ParseklogEntry *self) {
	Py_XDECREF(self->klog);

	self->ob_type->tp_free((PyObject *)self);
}

static PyMemberDef ParseklogEntry_members[] = {
	{"klog", T_OBJECT_EX, offsetof(ParseklogEntry, klog)},
	{"flags", T_INT, offsetof(ParseklogEntry, flags)},
	{"sysnum", T_INT, offsetof(ParseklogEntry, sysnum)},
	{"index", T_LONGLONG, offsetof(ParseklogEntry, index)},
	{"retparams", T_OBJECT_EX, offsetof(ParseklogEntry, retparams)},
	{"start_clock", T_ULONG, offsetof(ParseklogEntry, start_clock)},
	{"stop_clock", T_ULONG, offsetof(ParseklogEntry, stop_clock)},
	{"retval", T_LONG, offsetof(ParseklogEntry, retval)},
	{"signal", T_OBJECT_EX, offsetof(ParseklogEntry, signal)},
	{NULL}
};


static PyMethodDef ParseklogEntry_methods[] = {
	/*
	{"dirty", (PyCFunction)ParseklogEntry_dirty, METH_NOARGS,
		"Updates the raw representation of the klog to match the represented one"},
		*/
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
    (reprfunc)ParseklogEntry_str,/*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    "ParseklogRaw log object (minimal wrapper for parseklib.h)",           /* tp_doc */
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

static PyObject *repsig_to_pysig(struct klog_signal *sig) {
	ParseklogSignal *base_signal = NULL;
	struct klog_signal *cur_sig = sig;
	struct klog_signal *next_sig;

	if (sig) {
		PyObject *none = Py_BuildValue("()");
		ParseklogSignal *cur_signal;
		base_signal = (ParseklogSignal *)
			PyObject_CallObject((PyObject *)&ParseklogSignalType, none);
		if (base_signal == NULL) {
			base_signal = NULL;
			Py_XDECREF(none);
			goto out;
		}

		memcpy(base_signal->raw, sig->raw, 172);

		base_signal->next = Py_None;
		base_signal->number = sig->sig.signr;

		cur_signal = base_signal;

		while (cur_sig) {
			ParseklogSignal *next_signal;
			next_sig = sig->next;

			next_signal = (ParseklogSignal*)Py_None;
			if (next_sig) {
				next_signal = (ParseklogSignal *)
					PyObject_CallObject((PyObject *)&ParseklogSignalType, none);
			}
			cur_signal->next = (PyObject *)next_signal;
			cur_signal->number = cur_sig->sig.signr;
			memcpy(cur_signal->raw, cur_sig->raw, 172);

			cur_signal = next_signal;
			cur_sig = next_sig;
		}

		Py_XDECREF(none);
	} else {
		base_signal = (void *)Py_None;
	}

out:
	return (PyObject *)base_signal;
}

static void populate_entry(ParseklogEntry *entry) {
	struct klog_result *res = entry->raw;

	assert(res);

	entry->index = res->index;
	entry->start_clock = res->start_clock;
	entry->stop_clock = res->stop_clock;
	entry->retval = res->retval;
	entry->sysnum = res->psr.sysnum;
	entry->flags = res->psr.flags;

	if (res->retparams) {
		entry->retparams = PyByteArray_FromStringAndSize(res->retparams,
				res->retparams_size);
		assert(res->retparams_size == PyByteArray_Size(entry->retparams));
	} else {
		entry->retparams = Py_None;
	}

	entry->signal = repsig_to_pysig(res->signal);
}


struct klog_signal *pysig_to_repsig(ParseklogSignal *signal) {
	struct klog_signal *ret;

	if (signal == (ParseklogSignal *)Py_None) {
		return NULL;
	}

	ret = malloc(sizeof(struct klog_signal));
	if (ret == NULL) {
		/* FIXME: error handling */
		assert(0);
	}

	/* Setup the data */
	memcpy(ret->raw, signal->raw, 172);
	ret->sig.signr = signal->number;

	/* Get the next */
	ret->next = pysig_to_repsig((ParseklogSignal *)signal->next);
	/* Update the next pointers as needed */
	if (ret->next) {
		ret->sig.next = &ret->next->sig;
	} else {
		ret->sig.next = NULL;
	}

	return ret;
}

void create_psr(struct klog_result *psr, ParseklogEntry *entry) {
	/* NOTE: Does not deal with signals at all! they are just passed through */

	/* Poopulate the raw values */
	psr->psr.flags = entry->flags;
	psr->psr.sysnum = entry->sysnum;
	psr->index = entry->index;
	psr->start_clock = entry->start_clock;
	psr->stop_clock = entry->stop_clock;
	psr->retval = entry->retval;

	/* Ugh... need to convert object to data... */
	if (entry->retparams != Py_None) {
		psr->retparams_size = PyByteArray_Size(entry->retparams);
		psr->retparams = PyByteArray_AsString(entry->retparams);
	/* If the new retparams are null and the old not, free the old */
	} else {
		psr->retparams = NULL;
		psr->retparams_size = 0;
	}

	psr->signal = pysig_to_repsig((ParseklogSignal *)entry->signal);
}

static PyObject *Parseklog_do_write(Parseklog *self, PyObject *args) {
	struct klog_result *psrs = NULL;
	ParseklogEntry *entry = NULL;
	PyObject *list;
	PyObject *itr;
	int fd;
	int rc;
	int i;

	rc = PyArg_ParseTuple(args, "Oi", &list, &fd);
	if (!rc) {
		PyErr_SetString(PyExc_ValueError, "Invalid Argument");
		return NULL;
	}

	psrs = malloc(PyList_Size(list) * sizeof(struct klog_result));
	/* Iterate the list */
	itr = PyList_Type.tp_iter(list);
	
	i = 0;
	while ((entry = (ParseklogEntry *)PyObject_CallMethod(itr, "next", "()")) != NULL) {
		psrs[i].log = self->log;
		create_psr(&psrs[i], entry);
		i++;
	}
	PyErr_Clear();

	parseklog_do_write_chunk(PyList_Size(list), psrs, fd);

	Py_XDECREF(itr);


	return Py_None;
}

static PyObject *Parseklog_get_next_psr(Parseklog *self, PyObject *args) {
	struct klog_result *res = NULL;
	PyObject *arglist = NULL;
	ParseklogEntry *entry = NULL;

	res = parseklog_get_next_psr(self->log);

	if (!res) {
		entry = (void *)Py_None;
		goto out;
	}

	arglist = Py_BuildValue("(O)", self);

	entry = (ParseklogEntry *)PyObject_CallObject((PyObject *)&ParseklogEntryType, arglist);
	if (entry == NULL) {
		goto out;
	}

	Py_XDECREF(arglist);

	assert(entry != NULL);

	entry->raw = res;

	populate_entry(entry);

out:
	return (PyObject *)entry;
}

static PyObject *Parseklog_read_next_chunk(Parseklog *self, PyObject *args) {
	parseklog_read_next_chunk(self->log);
	return Py_None;
}

static PyObject *Parseklog_cur_chunk_size(Parseklog *self, PyObject *args) {
	int size = parseklog_cur_chunk_size(self->log);

	return PyInt_FromLong(size);
}

static PyObject *Parseklog_write_chunk(Parseklog *self, PyObject *args) {
	int fd;
	int rc;
	
	rc = PyArg_ParseTuple(args, "i", &fd);
	if (rc) {
		PyErr_SetString(PyExc_ValueError, "Invalid Argument");
		return NULL;
	}

	rc = parseklog_write_chunk(self->log, fd);
	if (rc) {
		PyErr_SetString(PyExc_OSError, "Failed to write out the log");
		return NULL;
	}

	return Py_None;
}

static PyMemberDef Parseklog_members[] = {
	{"filename", T_OBJECT_EX, offsetof(Parseklog, filename)},
	{NULL}
};

static PyMethodDef Parseklog_methods[] = {
	{"do_write", (PyCFunction)Parseklog_do_write, METH_VARARGS,
		"Writes a list of psrs passed in to a list"},
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
initparseklograw(void) {
	PyObject *m;

	if (PyType_Ready(&ParseklogType) < 0) {
		return;
	}

	if (PyType_Ready(&ParseklogEntryType) < 0) {
		return;
	}

	if (PyType_Ready(&ParseklogSignalType) < 0) {
		return;
	}

	m = Py_InitModule3("parseklograw", module_methods,
			"Module to facilitate klog parsing from python");

	if (m == NULL) {
		return;
	}

	Py_INCREF(&ParseklogType);
	Py_INCREF(&ParseklogEntryType);
	Py_INCREF(&ParseklogSignalType);
	PyObject_SetAttrString(m, "SR_HAS_RETPARAMS",
			PyInt_FromLong(SR_HAS_RETPARAMS));
	PyObject_SetAttrString(m, "SR_HAS_SIGNAL",
			PyInt_FromLong(SR_HAS_SIGNAL));
	PyObject_SetAttrString(m, "SR_HAS_START_CLOCK_SKIP",
			PyInt_FromLong(SR_HAS_START_CLOCK_SKIP));
	PyObject_SetAttrString(m, "SR_HAS_STOP_CLOCK_SKIP",
			PyInt_FromLong(SR_HAS_STOP_CLOCK_SKIP));
	PyObject_SetAttrString(m, "SR_HAS_NONZERO_RETVAL",
			PyInt_FromLong(SR_HAS_NONZERO_RETVAL));
	PyModule_AddObject(m, "ParseklogRaw", (PyObject *)&ParseklogType);
	PyModule_AddObject(m, "ParseklogEntryRaw", (PyObject *)&ParseklogEntryType);
	PyModule_AddObject(m, "ParseklogSignal", (PyObject *)&ParseklogSignalType);
}

/*
int main(int argc, char *argv[]) {
	Py_SetProgramName(argv[0]);

	Py_Initialize();
}
*/

