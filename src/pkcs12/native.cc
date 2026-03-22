#include <memory>
#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/provider.h>

#include <string>

static PyObject *OpenSSLError = NULL;

static int native_module_exec(PyObject *m) {
  if (OpenSSLError != NULL) {
    PyErr_SetString(PyExc_ImportError,
                    "cannot initialize spam module more than once");
    return -1;
  }
  OpenSSLError = PyErr_NewException("pkcs12.OpenSSLError", NULL, NULL);
  if (PyModule_AddObjectRef(m, "OpenSSLError", OpenSSLError) < 0) {
    return -1;
  }

  return 0;
}

namespace openssl {
struct Provider {
  OSSL_PROVIDER *provider;
  Provider(const std::string &name)
      : provider(OSSL_PROVIDER_load(NULL, name.c_str())) {}
  ~Provider() { OSSL_PROVIDER_unload(provider); }
};

struct X509Certificate {
  ::X509 *certificate;

  X509Certificate(::X509 *certificate) : certificate(certificate) {}

  ~X509Certificate() { ::X509_free(certificate); }
};

struct BIO {
  ::BIO *bio;

  BIO() : bio(::BIO_new(BIO_s_mem())) {}
  BIO(const Py_buffer &buffer)
      : bio(::BIO_new_mem_buf(buffer.buf, buffer.len)) {}
  ~BIO() { ::BIO_free(bio); }
};

namespace pkcs12 {

struct PKCS12 {
  ::PKCS12 *pkcs12;
  std::string password;

  PKCS12(const openssl::BIO &data, const std::string &password)
      : pkcs12(d2i_PKCS12_bio(data.bio, NULL)), password(password) {}

  struct AuthSafes {
    STACK_OF(PKCS7) * asafes;
  };

  struct SafeBag {
    ::PKCS12_SAFEBAG *bag;

    X509Certificate get_certificate() {
      return X509Certificate(PKCS12_SAFEBAG_get1_cert(bag));
    }
  };
};

} // namespace pkcs12
} // namespace openssl

static PyObject *load_certificates(PyObject *self, PyObject *args) {
  Py_buffer pkcs12_data;
  const char *pass;

  if (!PyArg_ParseTuple(args, "y*s", &pkcs12_data, &pass))
    return NULL;

  BIO *pkcs12_bio = BIO_new_mem_buf(pkcs12_data.buf, pkcs12_data.len);

  X509 *cert = NULL;
  STACK_OF(X509) *ca = NULL;
  STACK_OF(PKCS7) *asafes = NULL;
  PKCS12 *p12 = NULL;
  PyObject *ret = NULL;
  BIO *bio_mem = BIO_new(BIO_s_mem());

  int passlen = -1;

  OSSL_PROVIDER *legacy_p = NULL;
  OSSL_PROVIDER *default_p = NULL;

  /* Load the default provider */
  default_p = OSSL_PROVIDER_load(NULL, "default");
  if (default_p == NULL) {
    PyErr_SetString(OpenSSLError, "Error: Failed to load the legacy provider");
    goto err;
  }

  /* Load the legacy provider */
  legacy_p = OSSL_PROVIDER_load(NULL, "legacy");
  if (legacy_p == NULL) {
    PyErr_SetString(OpenSSLError, "Error: Failed to load the legacy provider");
    goto err;
  }

  p12 = d2i_PKCS12_bio(pkcs12_bio, NULL);
  if (p12 == NULL) {
    PyErr_SetString(OpenSSLError, "Error reading PKCS#12 file");
    // ERR_print_errors_fp(stderr);
    goto err;
  }
  if ((asafes = PKCS12_unpack_authsafes(p12)) == NULL) {
    PyErr_SetString(OpenSSLError, "Error reading PKCS#12 file");
    goto err;
  }

  int n = sk_PKCS7_num(asafes);
  for (int i = 0; i < n; i++) {
    STACK_OF(PKCS12_SAFEBAG) *bags = NULL;

    PKCS7 *p7 = sk_PKCS7_value(asafes, i);
    int bagnid = OBJ_obj2nid(p7->type);
    if (bagnid == NID_pkcs7_data) {
      bags = PKCS12_unpack_p7data(p7);
    } else if (bagnid == NID_pkcs7_encrypted) {
      bags = PKCS12_unpack_p7encdata(p7, pass, passlen);
    } else {
      continue;
    }
    if (bags == NULL) {
      // PyErr_SetString(OpenSSLError, "Failed to read PKCS7 bags");
      PyErr_SetString(OpenSSLError, "Invalid password");
      goto err;
    }
    int m = sk_PKCS12_SAFEBAG_num(bags);
    for (int j = 0; j < m; j++) {
      PKCS12_SAFEBAG *bag = sk_PKCS12_SAFEBAG_value(bags, j);
      X509 *cert = PKCS12_SAFEBAG_get1_cert(bag);
      if (cert != NULL) {
        int ret = PEM_write_bio_X509(bio_mem, cert);
        X509_free(cert);
        if (!ret) {
          PyErr_SetString(OpenSSLError, "Failed to get certificates data");
          goto err;
        }
      }
    }
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
  }

  char *pem_string = NULL;
  long len = BIO_get_mem_data(bio_mem, &pem_string);
  if (len <= 0) {
    PyErr_SetString(OpenSSLError, "Failed to export certificates data");
    goto err;
  }

  ret = PyBytes_FromStringAndSize(pem_string, len);

err:
  sk_PKCS7_pop_free(asafes, PKCS7_free);
  X509_free(cert);
  OSSL_STACK_OF_X509_free(ca);
  BIO_free(bio_mem);

  OSSL_PROVIDER_unload(legacy_p);
  OSSL_PROVIDER_unload(default_p);
  return ret;
}

static PyMethodDef methods[] = {
    {"load_certificates", load_certificates, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL} /* sentinel */
};

static PyModuleDef_Slot slots[] = {{Py_mod_exec, (void *)native_module_exec},
                                   {0, NULL}};

static struct PyModuleDef module = {
    .m_base = PyModuleDef_HEAD_INIT,
    .m_name = "native",
    .m_size = 0,
    .m_methods = methods,
    .m_slots = slots,
};

PyMODINIT_FUNC PyInit_native(void) { return PyModuleDef_Init(&module); }
