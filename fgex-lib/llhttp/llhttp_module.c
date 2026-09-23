#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include "lib/llhttp.h"

#define STRING(x) #x
#define XSTRING(x) STRING(x)
#define LLHTTP_VERSION XSTRING(LLHTTP_VERSION_MAJOR) "." XSTRING(LLHTTP_VERSION_MINOR) "." XSTRING(LLHTTP_VERSION_PATCH)

/* What this module is called, in one place. It is the name the types and the exception
 * classes carry, and the name they are looked back up under at runtime. It used to be
 * `pyllhttp` — the archived package this binding was forked from — which is not a
 * dependency and is not installed anywhere this is shipped. */
#define MODULE_NAME "firegex._llhttp"

typedef struct{
    PyObject_HEAD
    llhttp_t llhttp;
} llhttp_obj_t;

typedef struct{
    llhttp_errno_t code;
    const char *name;
} error_info;

static error_info errors[] = {
    #define HTTP_ERRNO_GEN(CODE, NAME, _) {CODE, #NAME},
    HTTP_ERRNO_MAP(HTTP_ERRNO_GEN)
    #undef HTTP_ERRNO_GEN
};

/*
 * `INVALID_METHOD` -> `InvalidMethodError`: the name this module publishes the
 * exception for that code under.
 *
 * Written into the caller's buffer every time, never cached on the table above. That
 * table is one array shared by every interpreter in the process, and this module
 * declares per-interpreter GIL support — a name stored there is a name two interpreters
 * can be writing at the same moment. It used to be `malloc`ed on first use, guarded by
 * a NULL check two threads can pass together, and never freed.
 */
static void error_class_name(const char *snake, char *out, size_t out_len) {
    size_t written = 0;
    bool upper = true;
    for (const char *c = snake; *c && written + 1 < out_len; ++c) {
        if (isalpha((unsigned char)*c))
            out[written++] = (char)(upper ? toupper((unsigned char)*c)
                                          : tolower((unsigned char)*c));
        else if (isdigit((unsigned char)*c))
            out[written++] = *c;
        upper = !isalpha((unsigned char)*c);
    }
    for (const char *suffix = "Error"; *suffix && written + 1 < out_len; ++suffix)
        out[written++] = *suffix;
    out[written] = '\0';
}

/*
 * The name of a method, by the number llhttp gives it, or NULL for a number it never
 * produces.
 *
 * A switch over `HTTP_ALL_METHOD_MAP` with the numbers as the case labels. This used to
 * be an array built from `HTTP_METHOD_MAP` and indexed with the method's number — but
 * that map is not the numbers in order: it runs 0 to 33 and then jumps to QUERY (46),
 * and PRI (34) and the RTSP methods (35 to 45) are not in it at all, although a request
 * parser accepts every one of them. So `QUERY / HTTP/1.1` read a name from past the end
 * of the array, PRI was reported as QUERY, and `FLUSH rtsp://x/ RTSP/1.0` — one line from
 * any client, sent to a service with an HTTP filter — crashed the process parsing it.
 * `llhttp_method_name` would give the same answers and `abort()` on anything else; this
 * answers NULL instead, because nothing a client sends may take the process down.
 */
static const char *method_name(uint8_t method) {
    switch (method) {
    #define HTTP_METHOD_GEN(NUMBER, NAME, STRING) case NUMBER: return #STRING;
    HTTP_ALL_METHOD_MAP(HTTP_METHOD_GEN)
    #undef HTTP_METHOD_GEN
    default:
        return NULL;
    }
}

/* New public callback helper that uses method names as C strings */
static int parser_callback(const char *name, llhttp_t *llhttp) {
    PyObject *result = PyObject_CallMethod(llhttp->data, name, NULL);
    if (result)
        Py_DECREF(result);

    if (PyErr_Occurred())
        return HPE_USER;

    if (HPE_PAUSED == llhttp_get_errno(llhttp)) {
        llhttp_resume(llhttp);
        return HPE_PAUSED;
    }

    if (HPE_PAUSED_UPGRADE == llhttp_get_errno(llhttp)) {
        llhttp_resume_after_upgrade(llhttp);
        return HPE_PAUSED_UPGRADE;
    }

    return HPE_OK;
}

static int parser_data_callback(const char *name, llhttp_t *llhttp, const char *data, size_t length) {
    PyObject *payload = PyMemoryView_FromMemory((char*)data, length, PyBUF_READ);
    if (!payload)
        return HPE_USER;
    PyObject *result = PyObject_CallMethod(llhttp->data, name, "O", payload);
    Py_DECREF(payload);
    if (result)
        Py_DECREF(result);

    if (PyErr_Occurred())
        return HPE_USER;

    if (HPE_PAUSED == llhttp_get_errno(llhttp)) {
        llhttp_resume(llhttp);
        return HPE_PAUSED;
    }

    if (HPE_PAUSED_UPGRADE == llhttp_get_errno(llhttp)) {
        llhttp_resume_after_upgrade(llhttp);
        return HPE_PAUSED_UPGRADE;
    }

    return HPE_OK;
}

/* Macros now simply pass the name as a string literal */
#define PARSER_CALLBACK(type) \
static int parser_ ## type (llhttp_t *llhttp) { \
    return parser_callback(#type, llhttp); \
}

#define PARSER_DATA_CALLBACK(type) \
static int parser_ ## type (llhttp_t *llhttp, const char *data, size_t length) { \
    return parser_data_callback(#type, llhttp, data, length); \
}

PARSER_CALLBACK(on_message_begin)
PARSER_DATA_CALLBACK(on_url)
PARSER_CALLBACK(on_url_complete)
PARSER_DATA_CALLBACK(on_status)
PARSER_CALLBACK(on_status_complete)
PARSER_DATA_CALLBACK(on_header_field)
PARSER_CALLBACK(on_header_field_complete)
PARSER_DATA_CALLBACK(on_header_value)
PARSER_CALLBACK(on_header_value_complete)
PARSER_CALLBACK(on_headers_complete)
PARSER_DATA_CALLBACK(on_body)
PARSER_CALLBACK(on_message_complete)
PARSER_CALLBACK(on_chunk_header)
PARSER_CALLBACK(on_chunk_complete)

llhttp_settings_t parser_settings = {
    .on_message_begin = parser_on_message_begin,
    .on_url = parser_on_url,
    .on_url_complete = parser_on_url_complete,
    .on_status = parser_on_status,
    .on_status_complete = parser_on_status_complete,
    .on_header_field = parser_on_header_field,
    .on_header_field_complete = parser_on_header_field_complete,
    .on_header_value = parser_on_header_value,
    .on_header_value_complete = parser_on_header_value_complete,
    .on_headers_complete = parser_on_headers_complete,
    .on_body = parser_on_body,
    .on_message_complete = parser_on_message_complete,
    .on_chunk_header = parser_on_chunk_header,
    .on_chunk_complete = parser_on_chunk_complete,
};

static PyObject *request_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
    PyObject *self = type->tp_alloc(type, 0);
    if (self) {
        llhttp_t *llhttp = &((llhttp_obj_t*)self)->llhttp;
        llhttp_init(llhttp, HTTP_REQUEST, &parser_settings);
        llhttp->data = self;
    }
    return self;
}

static PyObject *response_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
    PyObject *self = type->tp_alloc(type, 0);
    if (self) {
        llhttp_t *llhttp = &((llhttp_obj_t*)self)->llhttp;
        llhttp_init(llhttp, HTTP_RESPONSE, &parser_settings);
        llhttp->data = self;
    }
    return self;
}

/*
 * Turn an llhttp error code into the exception this module publishes for it.
 *
 * The classes are looked up in the module itself — `sys.modules` belongs to the
 * interpreter asking, so each one finds the classes it built, which is the whole reason
 * they are created per module instance rather than once per process.
 *
 * This used to import `pyllhttp`, a package that is not a dependency and is installed
 * nowhere the wheel is: the import failed, its traceback was printed to stderr (the
 * service log, on a filter), and the function returned **without setting an exception**,
 * which CPython reports to the caller as `SystemError: ... returned NULL without setting
 * an exception`. A malformed request — the traffic this exists to inspect — said that
 * instead of naming the parse error. So every path out of here raises something.
 */
static void set_related_exception(llhttp_errno_t eno, llhttp_t *llhttp) {
    const char *reason = llhttp_get_error_reason(llhttp);
    if (!reason)
        reason = "HTTP parse error";

    for (size_t i = 0; i < sizeof(errors)/sizeof(errors[0]); ++i) {
        if (errors[i].code != eno)
            continue;

        char class_name[128];
        error_class_name(errors[i].name, class_name, sizeof(class_name));

        PyObject *module = PyImport_ImportModule(MODULE_NAME);
        if (module) {
            PyObject *exception = PyObject_GetAttrString(module, class_name);
            Py_DECREF(module);
            if (exception) {
                PyErr_SetString(exception, reason);
                Py_DECREF(exception);
                return;
            }
        }
        /* The class is missing, which should not happen — but the traffic was still
         * malformed, and saying so badly beats saying nothing. */
        PyErr_Clear();
        PyErr_Format(PyExc_RuntimeError, "%s: %s", class_name, reason);
        return;
    }
    PyErr_Format(PyExc_RuntimeError,
                 "unknown HTTP parser error %d: %s", (int)eno, reason);
}

static PyObject *parser_execute(PyObject *self, PyObject *payload) {
    llhttp_t *llhttp = &((llhttp_obj_t*)self)->llhttp;

    Py_buffer buffer;
    if (PyObject_GetBuffer(payload, &buffer, PyBUF_SIMPLE)){
        return NULL;
    }

    if (!PyBuffer_IsContiguous(&buffer, 'C')) {
        PyErr_SetString(PyExc_TypeError, "buffer is not contiguous");
        PyBuffer_Release(&buffer);
        return NULL;
    }

    llhttp_errno_t error = llhttp_execute(llhttp, buffer.buf, buffer.len);

    PyBuffer_Release(&buffer);

    if (PyErr_Occurred())
        return NULL;

    switch (error) {
    case HPE_OK:
        return Py_BuildValue("(nn)", error, buffer.len);
    case HPE_PAUSED:
    case HPE_PAUSED_UPGRADE:
    case HPE_PAUSED_H2_UPGRADE:
        return Py_BuildValue("(nn)", error, llhttp->error_pos - (const char*)buffer.buf);
    default:
        set_related_exception(error, llhttp);
        return NULL;
    }
}

static PyObject *parser_pause(PyObject *self) {
    llhttp_t *llhttp = &((llhttp_obj_t*)self)->llhttp;
    llhttp_pause(llhttp);
    Py_RETURN_NONE;
}

static PyObject *parser_unpause(PyObject *self) {
    llhttp_t *llhttp = &((llhttp_obj_t*)self)->llhttp;
    llhttp_resume(llhttp);
    Py_RETURN_NONE;
}

static PyObject *parser_upgrade(PyObject *self) {
    llhttp_t *llhttp = &((llhttp_obj_t*)self)->llhttp;
    llhttp_resume_after_upgrade(llhttp);
    Py_RETURN_NONE;
}

static PyObject *parser_finish(PyObject *self) {
    llhttp_t *llhttp = &((llhttp_obj_t*)self)->llhttp;

    llhttp_errno_t error = llhttp_finish(llhttp);
    if (HPE_OK == error)
        Py_RETURN_NONE;

    set_related_exception(error, llhttp);
    return NULL;
}

static PyObject *parser_reset(PyObject *self) {
    llhttp_t *llhttp = &((llhttp_obj_t*)self)->llhttp;
    llhttp_reset(llhttp);
    Py_RETURN_NONE;
}

static PyObject * parser_dummy_noargs(PyObject *self) { Py_RETURN_NONE; }
static PyObject * parser_dummy_onearg(PyObject *self, PyObject *arg) { Py_RETURN_NONE; }

static PyMethodDef parser_methods[] = {
    { "execute", (PyCFunction)parser_execute, METH_O },
    { "pause", (PyCFunction)parser_pause, METH_NOARGS },
    { "unpause", (PyCFunction)parser_unpause, METH_NOARGS },
    { "upgrade", (PyCFunction)parser_upgrade, METH_NOARGS },
    { "finish", (PyCFunction)parser_finish, METH_NOARGS },
    { "reset", (PyCFunction)parser_reset, METH_NOARGS },
    { "on_message_begin", (PyCFunction)parser_dummy_noargs, METH_NOARGS },
    { "on_url", (PyCFunction)parser_dummy_onearg, METH_O },
    { "on_url_complete", (PyCFunction)parser_dummy_noargs, METH_NOARGS },
    { "on_status", (PyCFunction)parser_dummy_onearg, METH_O },
    { "on_status_complete", (PyCFunction)parser_dummy_noargs, METH_NOARGS },
    { "on_header_field", (PyCFunction)parser_dummy_onearg, METH_O },
    { "on_header_field_complete", (PyCFunction)parser_dummy_noargs, METH_NOARGS },
    { "on_header_value", (PyCFunction)parser_dummy_onearg, METH_O },
    { "on_header_value_complete", (PyCFunction)parser_dummy_noargs, METH_NOARGS },
    { "on_headers_complete", (PyCFunction)parser_dummy_noargs, METH_NOARGS },
    { "on_body", (PyCFunction)parser_dummy_onearg, METH_O },
    { "on_message_complete", (PyCFunction)parser_dummy_noargs, METH_NOARGS },
    { "on_chunk_header", (PyCFunction)parser_dummy_noargs, METH_NOARGS },
    { "on_chunk_complete", (PyCFunction)parser_dummy_noargs, METH_NOARGS },
    { NULL }
};

static PyObject *parser_method(PyObject *self, void *closure) {
    llhttp_t *llhttp = &((llhttp_obj_t*)self)->llhttp;
    if (llhttp->type != HTTP_REQUEST)
        Py_RETURN_NONE;
    if (!llhttp->http_major && !llhttp->http_minor)
        Py_RETURN_NONE;

    const char *name = method_name(llhttp->method);
    if (!name)
        Py_RETURN_NONE;
    return PyUnicode_FromString(name);
}

static PyObject *parser_major(PyObject *self, void *closure) {
    llhttp_t *llhttp = &((llhttp_obj_t*)self)->llhttp;
    if (!llhttp->http_major && !llhttp->http_minor)
        Py_RETURN_NONE;

    return PyLong_FromUnsignedLong(llhttp->http_major);
}

static PyObject *parser_minor(PyObject *self, void *closure) {
    llhttp_t *llhttp = &((llhttp_obj_t*)self)->llhttp;
    if (!llhttp->http_major && !llhttp->http_minor)
        Py_RETURN_NONE;

    return PyLong_FromUnsignedLong(llhttp->http_minor);
}

/* The numeric status of a response.
 *
 * llhttp has had it all along — it is a field on the parser struct, and
 * `llhttp_get_status_code` reads it — but this binding never exposed it, so the only
 * thing reachable from Python was the reason phrase the server wrote beside it. A filter
 * asking "was this a 500?" could not be answered at all.
 *
 * `None` for a request, which has no status, and before a response line has been read:
 * llhttp leaves the field at zero there, and zero is not a status code. */
static PyObject *parser_status_code(PyObject *self, void *closure) {
    llhttp_t *llhttp = &((llhttp_obj_t*)self)->llhttp;
    if (llhttp->type != HTTP_RESPONSE)
        Py_RETURN_NONE;
    if (!llhttp->status_code)
        Py_RETURN_NONE;

    return PyLong_FromUnsignedLong(llhttp_get_status_code(llhttp));
}

static PyObject *parser_content_length(PyObject *self, void *closure) {
    llhttp_t *llhttp = &((llhttp_obj_t*)self)->llhttp;
    if (!(llhttp->flags & F_CONTENT_LENGTH))
        Py_RETURN_NONE;

    return PyLong_FromUnsignedLong(llhttp->content_length);
}

static bool get_lenient(const llhttp_t *llhttp, llhttp_lenient_flags_t flag) {
    return llhttp->lenient_flags & flag;
}

static int set_lenient(llhttp_t *llhttp, llhttp_lenient_flags_t flag, bool value) {
    if (value) {
        llhttp->lenient_flags |= flag;
    } else {
        llhttp->lenient_flags &= ~flag;
    }
    return 0;
}

#define LENIENT_FLAG(name) \
static PyObject * \
parser_get_lenient_ ## name(PyObject *self, void *closure) \
    { return PyBool_FromLong(get_lenient(&((llhttp_obj_t*)self)->llhttp, LENIENT_ ## name)); } \
\
static int \
parser_set_lenient_ ## name(PyObject *self, PyObject *value, void *closure) \
    { return set_lenient(&((llhttp_obj_t*)self)->llhttp, LENIENT_ ## name, PyObject_IsTrue(value)); }

LENIENT_FLAG(HEADERS);
LENIENT_FLAG(CHUNKED_LENGTH);
LENIENT_FLAG(KEEP_ALIVE);
LENIENT_FLAG(TRANSFER_ENCODING);
LENIENT_FLAG(VERSION);

static PyObject *parser_get_lenient_headers(PyObject *self, void *closure) {
    llhttp_t *llhttp = &((llhttp_obj_t*)self)->llhttp;
    return PyBool_FromLong(llhttp->lenient_flags & LENIENT_HEADERS);
}

static int parser_set_lenient_headers(PyObject *self, PyObject *value, void *closure) {
    llhttp_t *llhttp = &((llhttp_obj_t*)self)->llhttp;
    llhttp_set_lenient_headers(llhttp, PyObject_IsTrue(value));
    return 0;
}

static PyObject *parser_get_lenient_chunked_length(PyObject *self, void *closure) {
    llhttp_t *llhttp = &((llhttp_obj_t*)self)->llhttp;
    return PyBool_FromLong(llhttp->lenient_flags & LENIENT_CHUNKED_LENGTH);
}

static int parser_set_lenient_chunked_length(PyObject *self, PyObject *value, void *closure) {
    llhttp_t *llhttp = &((llhttp_obj_t*)self)->llhttp;
    llhttp_set_lenient_chunked_length(llhttp, PyObject_IsTrue(value));
    return 0;
}

static PyObject *parser_get_lenient_keep_alive(PyObject *self, void *closure) {
    llhttp_t *llhttp = &((llhttp_obj_t*)self)->llhttp;
    return PyBool_FromLong(llhttp->lenient_flags & LENIENT_KEEP_ALIVE);
}

static int parser_set_lenient_keep_alive(PyObject *self, PyObject *value, void *closure) {
    llhttp_t *llhttp = &((llhttp_obj_t*)self)->llhttp;
    llhttp_set_lenient_keep_alive(llhttp, PyObject_IsTrue(value));
    return 0;
}

static PyObject *parser_message_needs_eof(PyObject *self, void *closure) {
    llhttp_t *llhttp = &((llhttp_obj_t*)self)->llhttp;
    return PyBool_FromLong(llhttp_message_needs_eof(llhttp));
}

static PyObject *parser_should_keep_alive(PyObject *self, void *closure) {
    llhttp_t *llhttp = &((llhttp_obj_t*)self)->llhttp;
    return PyBool_FromLong(llhttp_should_keep_alive(llhttp));
}

static PyObject *parser_is_paused(PyObject *self, void *closure) {
    llhttp_t *llhttp = &((llhttp_obj_t*)self)->llhttp;
    return PyBool_FromLong(HPE_PAUSED == llhttp_get_errno(llhttp));
}

static PyObject *parser_is_upgrading(PyObject *self, void *closure) {
    llhttp_t *llhttp = &((llhttp_obj_t*)self)->llhttp;
    switch (llhttp_get_errno(llhttp)) {
    case HPE_PAUSED_UPGRADE:
    case HPE_PAUSED_H2_UPGRADE:
        Py_RETURN_TRUE;
        break;
    default:
         Py_RETURN_FALSE;
         break;
    }
}

static PyObject *parser_is_busted(PyObject *self, void *closure) {
    llhttp_t *llhttp = &((llhttp_obj_t*)self)->llhttp;
    switch (llhttp_get_errno(llhttp)) {
    case HPE_OK:
    case HPE_PAUSED:
    case HPE_PAUSED_UPGRADE:
        Py_RETURN_FALSE;
    default:
        Py_RETURN_TRUE;
    }
}

static PyObject *parser_error(PyObject *self,  void *closure) {
    llhttp_t *llhttp = &((llhttp_obj_t*)self)->llhttp;
    if (HPE_OK == llhttp_get_errno(llhttp))
        Py_RETURN_NONE;
    return PyUnicode_FromString(llhttp_get_error_reason(llhttp));
}

static PyGetSetDef parser_getset[] = {
    { "method", parser_method },
    { "status_code", parser_status_code },
    { "major", parser_major },
    { "minor", parser_minor },
    { "content_length", parser_content_length },
    { "lenient_headers", parser_get_lenient_HEADERS, parser_set_lenient_HEADERS },
    { "lenient_chunked_length", parser_get_lenient_CHUNKED_LENGTH, parser_set_lenient_CHUNKED_LENGTH },
    { "lenient_keep_alive", parser_get_lenient_KEEP_ALIVE, parser_set_lenient_KEEP_ALIVE },
    { "lenient_transfer_encoding", parser_get_lenient_TRANSFER_ENCODING, parser_set_lenient_TRANSFER_ENCODING },
    { "lenient_version", parser_get_lenient_VERSION, parser_set_lenient_VERSION },
    { "message_needs_eof", parser_message_needs_eof },
    { "should_keep_alive", parser_should_keep_alive },
    { "is_paused", parser_is_paused },
    { "is_upgrading", parser_is_upgrading },
    { "is_busted", parser_is_busted },
    { "error", parser_error },
    { NULL }
};

static void parser_dealloc(PyObject *self) {
    llhttp_obj_t *llhttp = (llhttp_obj_t*)self;
    Py_TYPE(self)->tp_free(self);
}

static PyType_Slot request_slots[] = {
    {Py_tp_doc, "llhttp request parser"},
    {Py_tp_new, request_new},
    {Py_tp_dealloc, parser_dealloc},
    {Py_tp_methods, parser_methods},
    {Py_tp_getset, parser_getset},
    {0, 0},
};

static PyType_Spec request_spec = {
    MODULE_NAME ".Request",
    sizeof(llhttp_obj_t),
    0,
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    request_slots,
};

static PyType_Slot response_slots[] = {
    {Py_tp_doc, "llhttp response parser"},
    {Py_tp_new, response_new},
    {Py_tp_dealloc, parser_dealloc},
    {Py_tp_methods, parser_methods},
    {Py_tp_getset, parser_getset},
    {0, NULL},
};

static PyType_Spec response_spec = {
    MODULE_NAME ".Response",
    sizeof(llhttp_obj_t),
    0, Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    response_slots,
};

/* One class per error code, per module instance: two subinterpreters must never share
 * an exception object, which is what `Py_MOD_PER_INTERPRETER_GIL_SUPPORTED` promises. */
static int add_error_classes(PyObject *m) {
    PyObject *base_error = PyErr_NewException(MODULE_NAME ".Error", NULL, NULL);
    if (!base_error)
        return -1;
    if (PyModule_AddObjectRef(m, "Error", base_error) < 0) {
        Py_DECREF(base_error);
        return -1;
    }

    for (size_t i = 0; i < sizeof(errors)/sizeof(errors[0]); ++i) {
        char class_name[128];
        char qualified_name[128 + sizeof(MODULE_NAME) + 1];
        error_class_name(errors[i].name, class_name, sizeof(class_name));
        snprintf(qualified_name, sizeof(qualified_name), MODULE_NAME ".%s", class_name);

        PyObject *exception = PyErr_NewException(qualified_name, base_error, NULL);
        if (!exception) {
            Py_DECREF(base_error);
            return -1;
        }
        int added = PyModule_AddObjectRef(m, class_name, exception);
        Py_DECREF(exception);
        if (added < 0) {
            Py_DECREF(base_error);
            return -1;
        }
    }

    Py_DECREF(base_error);
    return 0;
}

static int add_type(PyObject *m, PyType_Spec *spec) {
    PyObject *type = PyType_FromSpec(spec);
    if (!type)
        return -1;
    /* The spec carries the dotted name; the module wants the last component of it. */
    int added = PyModule_AddObjectRef(m, spec->name + strlen(MODULE_NAME "."), type);
    Py_DECREF(type);
    return added;
}

static int init_llhttp_module(PyObject *m) {
    if (PyModule_AddStringConstant(m, "version", LLHTTP_VERSION) < 0)
        goto fail;

    for (size_t i = 0; i < sizeof(errors)/sizeof(errors[0]); ++i) {
        if (PyModule_AddIntConstant(m, errors[i].name, errors[i].code) < 0)
            goto fail;
    }

    if (add_error_classes(m) < 0)
        goto fail;

    if (add_type(m, &request_spec) < 0)
        goto fail;

    if (add_type(m, &response_spec) < 0)
        goto fail;

    return 0;

fail:
    /* The module belongs to the import machinery, which destroys it when a `Py_mod_exec`
     * slot fails; releasing it here as well handed back a reference that was never ours.
     * Whatever raised first is the useful message, so nothing is overwritten either. */
    if (!PyErr_Occurred())
        PyErr_SetString(PyExc_RuntimeError, "Failed to initialize the llhttp module");
    return -1;
}


static PyModuleDef_Slot llhttp_slots[] = {
    {Py_mod_exec, init_llhttp_module},
    /* Declared where it exists — the slot arrived with per-interpreter GILs in 3.12, and
     * the package supports interpreters older than that. Before 3.12 there is nothing to
     * declare: every subinterpreter shares the one GIL. */
#if PY_VERSION_HEX >= 0x030C0000
    {Py_mod_multiple_interpreters, Py_MOD_PER_INTERPRETER_GIL_SUPPORTED},
#endif
    {0, NULL}
};

static struct PyModuleDef llhttp_module = {
    PyModuleDef_HEAD_INIT,
    .m_name = "firegex._llhttp",
    .m_doc = "llhttp wrapper",
    .m_slots = llhttp_slots,
    .m_size = 0,
};


PyMODINIT_FUNC
PyInit__llhttp(void) {
    return PyModuleDef_Init(&llhttp_module);
}



