#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <vector>

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
class InvalidPKCS12File : std::exception {};
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

  BIO() : bio(::BIO_new(::BIO_s_mem())) {}
  BIO(const Py_buffer &buffer)
      : bio(::BIO_new_mem_buf(buffer.buf, buffer.len)) {}
  ~BIO() { ::BIO_free(bio); }

  BIO &operator<<(const X509Certificate &certificate) {
    int ret = PEM_write_bio_X509(bio, certificate.certificate);
    return *this;
  }
};

struct SafeBag {
  ::PKCS12_SAFEBAG *bag;

  SafeBag(::PKCS12_SAFEBAG *bag) : bag(bag) {}

  std::optional<X509Certificate> get_certificate() {
    X509 *cert = PKCS12_SAFEBAG_get1_cert(bag);
    if (cert == NULL) {
      return std::nullopt;
    }
    // вот тут нюанс -- тут будет конструирование X509Certificate по месту
    // иначе копирование и вызов деструктора, а умные указатели мне пока
    // использовать не хочется
    return cert;
  }

  ~SafeBag() {}
};

struct PKCS12 {

  using _PKCS12 =
      std::unique_ptr<::PKCS12, decltype([](::PKCS12 *p) { PKCS12_free(p); })>;
  using _AuthenticatedSafes =
      std::unique_ptr<STACK_OF(PKCS7), decltype([](STACK_OF(PKCS7) * p) {
                        sk_PKCS7_pop_free(p, PKCS7_free);
                      })>;
  using _SafeContents =
      std::unique_ptr<STACK_OF(PKCS12_SAFEBAG),
                      decltype([](STACK_OF(PKCS12_SAFEBAG) * p) {
                        sk_PKCS12_SAFEBAG_pop_free(p, PKCS12_SAFEBAG_free);
                      })>;

  _PKCS12 pkcs12;
  _AuthenticatedSafes authenticated_safes;
  std::vector<_SafeContents> safe_contents_stacks;

  PKCS12(const openssl::BIO &data, const std::string &password)
      : pkcs12(d2i_PKCS12_bio(data.bio, NULL)),
        authenticated_safes(get_authenticated_safes(pkcs12.get())),
        safe_contents_stacks(
            get_safe_contents_stacks(authenticated_safes.get(), password)) {}

  static STACK_OF(PKCS7) * get_authenticated_safes(::PKCS12 *pkcs12) {
    if (pkcs12 == NULL) {
      throw InvalidPKCS12File();
    }
    return PKCS12_unpack_authsafes(pkcs12);
  }
  static std::vector<_SafeContents>
  get_safe_contents_stacks(STACK_OF(PKCS7) * authenticated_safes,
                           const std::string &password) {
    if (authenticated_safes == NULL) {
      throw InvalidPKCS12File();
    }
    std::vector<_SafeContents> result;

    for (int i = 0; i < sk_PKCS7_num(authenticated_safes); ++i) {
      ::PKCS7 *pkcs7 = sk_PKCS7_value(authenticated_safes, i);
      int bagnid = OBJ_obj2nid(pkcs7->type);
      STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
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
      result.emplace_back(bags);
    }
    return result;
  }

  class iterator {
    using outer_iterator = std::vector<_SafeContents>::iterator;

    outer_iterator outer;
    int inner;

  public:
    using iterator_category = std::input_iterator_tag;
    using value_type = SafeBag;
    using difference_type = int;
    using pointer = SafeBag *;
    using reference = SafeBag &;
    iterator(outer_iterator outer, int inner = 0)
        : outer(outer), inner(inner) {}
    iterator &operator++() {
      ++inner;
      if (inner >= sk_PKCS12_SAFEBAG_num(outer->get())) {
        ++outer;
        inner = 0;
      }
      return *this;
    }
    iterator operator++(int) {
      auto retval = *this;
      ++(*this);
      return retval;
    }
    bool operator==(iterator other) const {
      return outer == other.outer and inner == other.inner;
    }
    bool operator!=(iterator other) const { return !(*this == other); }
    value_type operator*() const {
      return SafeBag(sk_PKCS12_SAFEBAG_value(outer->get(), inner));
    }
  };
  iterator begin() { return iterator(safe_contents_stacks.begin()); }
  iterator end() { return iterator(safe_contents_stacks.end()); }
};

} // namespace openssl

namespace python {
PyObject *make_bytes(const openssl::BIO &bio) {
  char *data = NULL;
  long len = BIO_get_mem_data(bio.bio, &data);
  // if (len <= 0) {
  //   PyErr_SetString(OpenSSLError, "Failed to export certificates data");
  //   goto err;
  // }

  return PyBytes_FromStringAndSize(data, len);
}
} // namespace python

extern "C" {
static PyObject *extract_certificates(PyObject *self, PyObject *args) {
  Py_buffer pkcs12_bytes;
  const char *password;

  if (!PyArg_ParseTuple(args, "y*s", &pkcs12_bytes, &password))
    return NULL;

  try {
    auto default_provider = openssl::Provider("default");
    auto legacy_provider = openssl::Provider("legacy");
    auto pkcs12_bio = openssl::BIO(pkcs12_bytes);
    auto pkcs12 = openssl::PKCS12(pkcs12_bio, password);
    auto output = openssl::BIO();

    for (auto bag : pkcs12) {
      if (auto certificate = bag.get_certificate()) {
        output << *certificate;
      }
    }

    return python::make_bytes(output);
  } catch (openssl::InvalidPKCS12File &_) {
    PyErr_SetString(OpenSSLError, "Invalid file");
    return NULL;
  } catch (openssl::InvalidPassword &_) {
    PyErr_SetString(OpenSSLError, "Invalid password");
    return NULL;
  }
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
