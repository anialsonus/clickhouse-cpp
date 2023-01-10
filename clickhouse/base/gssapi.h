#if WITH_GSSAPI
#   include <gssapi/gssapi.h>
#   include <gssapi/gssapi_ext.h>
#   define MAYBE_NORETURN
#else
#   define MAYBE_NORETURN [[noreturn]]
#endif

namespace clickhouse {

class Credentials
{
public:
    explicit Credentials() = default;
    explicit Credentials(const std::string & user_name_);

    virtual ~Credentials() = default;

    const std::string & getUserName() const;
    bool isReady() const;

protected:
    [[noreturn]] static void throwNotReady();

    bool is_ready = false;
    std::string user_name;
};


class GSSInitiatorContext
    : public Credentials
{
public:
    struct Params
    {
        std::string mechanism = "1.2.840.113554.1.2.2"; // OID: krb5
        std::string principal;
        std::string realm;
        std::string target;
    };

    explicit GSSInitiatorContext(const Params & params_);
    virtual ~GSSInitiatorContext() override;

    GSSInitiatorContext(const GSSInitiatorContext &) = delete;
    GSSInitiatorContext(GSSInitiatorContext &&) = delete;
    GSSInitiatorContext & operator= (const GSSInitiatorContext &) = delete;
    GSSInitiatorContext & operator= (GSSInitiatorContext &&) = delete;

    const std::string & getRealm() const;
    bool isFailed() const;
    MAYBE_NORETURN std::string processToken(const std::string & input_token);

private:
    void reset();
    void resetHandles() noexcept;
    void initHandles();

    const Params params;

    bool is_failed = false;
    std::string realm;

#if WITH_GSSAPI
    gss_ctx_id_t context_handle_ = GSS_C_NO_CONTEXT;
    gss_ctx_id_t * context_handle = &context_handle_;
    gss_cred_id_t initiator_credentials_handle = GSS_C_NO_CREDENTIAL;
    gss_name_t initiator_name;
    gss_name_t target_name;
#endif
};

// class KerberosSocketFactory : public NonSecureSocketFactory {
// public:
//     explicit KerberosSocketFactory(const ClientOptions& opts);
//     ~KerberosSocketFactory() override;

// protected:
//     std::unique_ptr<Socket> doConnect(const NetworkAddress& address, const ClientOptions& opts) override;

// private:
//     const SSLParams ssl_params_;
//     std::unique_ptr<SSLContext> ssl_context_;
// };


}
