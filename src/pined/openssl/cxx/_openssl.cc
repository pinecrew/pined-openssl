#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <pybind11/pybind11.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/provider.h>

namespace py = pybind11;

namespace openssl {

class InvalidPassword : public std::invalid_argument {
public:
  InvalidPassword() : std::invalid_argument("Invalid password") {}
};
class InvalidPKCS12File : public std::invalid_argument {
public:
  InvalidPKCS12File() : std::invalid_argument("Invalid PKCS12 data") {}
};

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
  BIO(const py::bytes &buffer) : bio(nullptr) {
    char *ptr;
    ssize_t len;
    PYBIND11_BYTES_AS_STRING_AND_SIZE(buffer.ptr(), &ptr, &len);
    bio = ::BIO_new_mem_buf(ptr, len);
  }
  ~BIO() { ::BIO_free(bio); }

  char *data() {
    char *result = NULL;
    ssize_t len = BIO_get_mem_data(bio, &result);
    return result;
  }

  size_t size() {
    char *result = NULL;
    return BIO_get_mem_data(bio, &result);
  }

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

py::bytes extract_certificates(py::bytes pkcs12_data, std::string password) {
  auto default_provider = openssl::Provider("default");
  auto legacy_provider = openssl::Provider("legacy");
  auto pkcs12_bio = openssl::BIO(pkcs12_data);
  auto pkcs12 = openssl::PKCS12(pkcs12_bio, password);
  auto output = openssl::BIO();

  for (auto bag : pkcs12) {
    if (auto certificate = bag.get_certificate()) {
      output << *certificate;
    }
  }
  return py::bytes(output.data(), output.size());
}

PYBIND11_MODULE(_openssl, m, py::mod_gil_not_used()) {
  py::register_local_exception<openssl::InvalidPassword>(m, "InvalidPassword", PyExc_ValueError);
  py::register_local_exception<openssl::InvalidPKCS12File>(m, "InvalidPKCS12File", PyExc_ValueError);

  m.doc() = "internal native openssl wrapper";
  m.def("extract_certificates", &extract_certificates,
        "Extract certificates from PKCS12 bundle");
}
