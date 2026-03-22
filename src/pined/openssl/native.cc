#include <exception>
#include <string>

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/provider.h>

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

class NoCertificateException : std::exception {};
class InvalidPassword : std::exception {};
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

  PyObject *to_bytes() const {
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    // if (len <= 0) {
    //   PyErr_SetString(OpenSSLError, "Failed to export certificates data");
    //   goto err;
    // }

    return PyBytes_FromStringAndSize(data, len);
  }

  BIO &operator<<(const X509Certificate &certificate) {
    int ret = PEM_write_bio_X509(bio, certificate.certificate);
    return *this;
  }
};

namespace pkcs12 {
struct SafeBag {
  ::PKCS12_SAFEBAG *bag;

  SafeBag(::PKCS12_SAFEBAG *bag) : bag(bag) {}

  X509Certificate get_certificate() throw(NoCertificateException) {
    X509 *cert = PKCS12_SAFEBAG_get1_cert(bag);
    if (cert == NULL) {
      throw NoCertificateException();
    }
    return X509Certificate(cert);
  }

  ~SafeBag() {}
};

struct PKCS7_ {
  ::PKCS7 *pkcs7;
  std::string password;
  STACK_OF(PKCS12_SAFEBAG) * bags;

  PKCS7_(::PKCS7 *pkcs7, const std::string &password)
      : pkcs7(pkcs7), password(password), bags(NULL) {
    int bagnid = OBJ_obj2nid(pkcs7->type);
    switch (bagnid) {
    case NID_pkcs7_data:
      bags = PKCS12_unpack_p7data(pkcs7);
      break;
    case NID_pkcs7_encrypted: {
      bags =
          PKCS12_unpack_p7encdata(pkcs7, password.c_str(), password.length());
      if (bags == NULL) {
        throw InvalidPassword();
      }
      break;
    }
    default:
      break;
    }
  }
  ~PKCS7_() { sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free); }

  class iterator
      : public std::iterator<std::input_iterator_tag, // iterator_category
                             SafeBag,                 // value_type
                             int,                     // difference_type
                             SafeBag *,               // pointer
                             SafeBag &                // reference
                             > {
    PKCS7_ &p;
    int i;

  public:
    explicit iterator(PKCS7_ &p, int i = 0) : p(p), i(i) {}
    iterator &operator++() {
      ++i;
      return *this;
    }
    iterator operator++(int) {
      iterator retval = *this;
      ++(*this);
      return retval;
    }
    bool operator==(iterator other) const { return i == other.i; }
    bool operator!=(iterator other) const { return !(*this == other); }
    value_type operator*() const {
      return SafeBag(sk_PKCS12_SAFEBAG_value(p.bags, i));
    }
  };
  iterator begin() { return iterator(*this, 0); }
  iterator end() {
    return iterator(*this, bags == NULL ? 0 : sk_PKCS12_SAFEBAG_num(bags));
  }
};

struct PKCS12 {
  ::PKCS12 *pkcs12;
  STACK_OF(PKCS7) * asafes;
  std::string password;

  PKCS12(const openssl::BIO &data, const std::string &password)
      : pkcs12(d2i_PKCS12_bio(data.bio, NULL)),
        asafes(PKCS12_unpack_authsafes(pkcs12)), password(password) {}
  ~PKCS12() {
    sk_PKCS7_pop_free(asafes, PKCS7_free);
    PKCS12_free(pkcs12);
  }
  class iterator
      : public std::iterator<std::input_iterator_tag, // iterator_category
                             PKCS7_,                  // value_type
                             int,                     // difference_type
                             PKCS7_ *,                // pointer
                             PKCS7_ &                 // reference
                             > {
    PKCS12 &p;
    int i;

  public:
    explicit iterator(PKCS12 &p, int i = 0) : p(p), i(i) {}
    iterator &operator++() {
      ++i;
      return *this;
    }
    iterator operator++(int) {
      iterator retval = *this;
      ++(*this);
      return retval;
    }
    bool operator==(iterator other) const { return i == other.i; }
    bool operator!=(iterator other) const { return !(*this == other); }
    value_type operator*() const {
      auto pkcs7 = sk_PKCS7_value(p.asafes, i);
      return PKCS7_(pkcs7, p.password);
    }
  };
  iterator begin() { return iterator(*this, 0); }
  iterator end() { return iterator(*this, sk_PKCS7_num(asafes)); }
};

} // namespace pkcs12
} // namespace openssl

extern "C" {
static PyObject *extract_certificates(PyObject *self, PyObject *args) {
  Py_buffer pkcs12_data;
  const char *pass;

  if (!PyArg_ParseTuple(args, "y*s", &pkcs12_data, &pass))
    return NULL;

  auto default_provider = openssl::Provider("default");
  auto legacy_provider = openssl::Provider("legacy");

  auto pkcs12_bio = openssl::BIO(pkcs12_data);

  auto pkcs12 = openssl::pkcs12::PKCS12(pkcs12_bio, pass);

  auto certificates_bio = openssl::BIO();

  try {
    for (auto pkcs7 : pkcs12) {
      for (auto bag : pkcs7) {
        try {
          certificates_bio << bag.get_certificate();
        } catch (openssl::NoCertificateException) {
        }
      }
    }
  } catch (openssl::InvalidPassword) {
    PyErr_SetString(OpenSSLError, "Invalid password");
    return NULL;
  }
  return certificates_bio.to_bytes();
}
}

static PyMethodDef methods[] = {
    {"extract_certificates", extract_certificates, METH_VARARGS, NULL},
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
