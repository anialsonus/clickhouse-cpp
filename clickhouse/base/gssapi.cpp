#include "../client.h"
#include "../exceptions.h"
#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_krb5.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include "gssapi.h"


#include <stdexcept>
#include <mutex>
#include <iostream>

namespace clickhouse
{

namespace ErrorCodes
{
    extern const int BAD_ARGUMENTS;
    extern const int FEATURE_IS_NOT_ENABLED_AT_BUILD_TIME;
    extern const int KERBEROS_ERROR;
}

GSSInitiatorContext::GSSInitiatorContext(const GSSInitiatorContext::Params & params_)
    : params(params_)
{
}

GSSInitiatorContext::~GSSInitiatorContext()
{
    std::cout << "GSSInitiatorContext dtor" << std::endl;
    resetHandles();
}

const std::string & GSSInitiatorContext::getRealm() const
{
    if (!isReady())
    {
        // throwNotReady();
        throw KerberosError("not ready (logical error)");
    }
    return realm;
}

bool GSSInitiatorContext::isFailed() const
{
    return is_failed;
}

bool Credentials::isReady() const
{
    return is_ready;
}


#if WITH_GSSAPI

namespace
{

std::recursive_mutex gss_global_mutex;

struct PrincipalName
{
    explicit PrincipalName(std::string principal);

    std::string name;
    std::vector<std::string> instances;
    std::string realm;
};

PrincipalName::PrincipalName(std::string principal)
{
    const auto at_pos = principal.find('@');
    if (at_pos != std::string::npos)
    {
        realm = principal.substr(at_pos + 1);
        principal.resize(at_pos);
    }

    // if (auto slash = principal.find("/"); slash != std::string::npos)
    // {
    //     auto pb = principal.begin();
    //     name.assign(pb, pb + slash);
    //     instances.assign(pb + slash + 1, principal.end());
    // }


    std::string::size_type start = 0;
    auto end = principal.find("/");
    bool name_assigned = false;
    while (end != std::string::npos)
    {
        if (!name_assigned)
        {
            name = principal.substr(start, end - start);
            name_assigned = true;
        }
        else
        {
            instances.push_back(principal.substr(start, end - start));
        }

        start = end + 1;
        end = principal.find("/", start);
    }


    // Poco::std::stringTokenizer st(principal, "/");
    // auto it = st.begin();
    // if (it != st.end())
    // {
    //     name = *it;
    //     instances.assign(++it, st.end());
    // }
}

std::string bufferToString(const gss_buffer_desc & buf)
{
    std::string str;

    if (buf.length > 0 && buf.value != nullptr)
    {
        str.assign(static_cast<char *>(buf.value), buf.length);
        while (!str.empty() && str.back() == '\0') { str.pop_back(); }
    }

    return str;
}

std::string extractSpecificStatusMessages(OM_uint32 status_code, int status_type, const gss_OID & mech_type)
{
    std::scoped_lock lock(gss_global_mutex);

    std::string messages;
    OM_uint32 message_context = 0;

    do
    {
        gss_buffer_desc status_string_buf;
        status_string_buf.length = 0;
        status_string_buf.value = nullptr;

        // SCOPE_EXIT({
        //     OM_uint32 minor_status = 0;
        //     [[maybe_unused]] OM_uint32 major_status = gss_release_buffer(
        //         &minor_status,
        //         &status_string_buf
        //     );
        // });

        OM_uint32 minor_status = 0;
        [[maybe_unused]] OM_uint32 major_status = gss_display_status(
            &minor_status,
            status_code,
            status_type,
            mech_type,
            &message_context,
            &status_string_buf
        );

        const auto message = bufferToString(status_string_buf);

        if (!message.empty())
        {
            if (!messages.empty())
                messages += ", ";

            messages += message;
        }

        major_status = gss_release_buffer(
            &minor_status,
            &status_string_buf
            );
    } while (message_context != 0);

    return messages;
}

std::string extractStatusMessages(OM_uint32 major_status_code, OM_uint32 minor_status_code, const gss_OID & mech_type)
{
    std::scoped_lock lock(gss_global_mutex);

    const auto gss_messages = extractSpecificStatusMessages(major_status_code, GSS_C_GSS_CODE, mech_type);
    const auto mech_messages = extractSpecificStatusMessages(minor_status_code, GSS_C_MECH_CODE, mech_type);

    std::string messages;

    if (!gss_messages.empty())
        messages += "Majors: " + gss_messages;

    if (!mech_messages.empty())
    {
        if (!messages.empty())
            messages += "; ";

        messages += "Minors: " + mech_messages;
    }

    return messages;
}

std::pair<std::string, std::string> extractNameAndRealm(const gss_name_t & name)
{
    std::scoped_lock lock(gss_global_mutex);

    gss_buffer_desc name_buf;
    name_buf.length = 0;
    name_buf.value = nullptr;

    // SCOPE_EXIT({
    //     OM_uint32 minor_status = 0;
    //     [[maybe_unused]] OM_uint32 major_status = gss_release_buffer(
    //         &minor_status,
    //         &name_buf
    //     );
    // });

    OM_uint32 minor_status = 0;
    [[maybe_unused]] OM_uint32 major_status = gss_display_name(
        &minor_status,
        name,
        &name_buf,
        nullptr
    );


    const PrincipalName principal(bufferToString(name_buf));

    major_status = gss_release_buffer(
        &minor_status,
        &name_buf
        );
    return { principal.name, principal.realm };
}

bool equalMechanisms(const std::string & left_str, const gss_OID & right_oid)
{
    std::scoped_lock lock(gss_global_mutex);

    gss_buffer_desc left_buf;
    left_buf.length = left_str.size();
    left_buf.value = const_cast<char *>(left_str.c_str());

    gss_OID left_oid = GSS_C_NO_OID;

    // SCOPE_EXIT({
    //     if (left_oid != GSS_C_NO_OID)
    //     {
    //         OM_uint32 minor_status = 0;
    //         [[maybe_unused]] OM_uint32 major_status = gss_release_oid(
    //             &minor_status,
    //             &left_oid
    //         );
    //         left_oid = GSS_C_NO_OID;
    //     }
    // });

    OM_uint32 minor_status = 0;
    OM_uint32 major_status = gss_str_to_oid(
        &minor_status,
        &left_buf,
        &left_oid
    );

    if (GSS_ERROR(major_status))
        return false;

    auto eq = gss_oid_equal(left_oid, right_oid);

    if (left_oid != GSS_C_NO_OID)
    {
        OM_uint32 minor_status = 0;
        [[maybe_unused]] OM_uint32 major_status = gss_release_oid(
            &minor_status,
            &left_oid
            );
        left_oid = GSS_C_NO_OID;
    }
    return eq;
}

}

void GSSInitiatorContext::reset()
{
    std::cout << "Top of GSSInitiatorContext::reset" << std::endl;
    is_ready = false;
    is_failed = false;
    user_name.clear();
    realm.clear();
    initHandles();
}

void GSSInitiatorContext::resetHandles() noexcept
{
    std::scoped_lock lock(gss_global_mutex);

    std::cout << "Top of GSSInitiatorContext::resetHandles" << std::endl;

    if (initiator_credentials_handle != GSS_C_NO_CREDENTIAL)
    {
        OM_uint32 minor_status = 0;
        [[maybe_unused]] OM_uint32 major_status = gss_release_cred(
            &minor_status,
            &initiator_credentials_handle
        );
        initiator_credentials_handle = GSS_C_NO_CREDENTIAL;
    }

    if (*context_handle != GSS_C_NO_CONTEXT)
    {
        OM_uint32 minor_status = 0;
        [[maybe_unused]] OM_uint32 major_status = gss_delete_sec_context(
            &minor_status,
            /* & */context_handle,
            GSS_C_NO_BUFFER
        );
        *context_handle = GSS_C_NO_CONTEXT;
    }
}

void GSSInitiatorContext::initHandles()
{
    // std::scoped_lock lock(gss_global_mutex);

    std::cout << "Top of GSSInitiatorContext::initHandles" << std::endl;


    resetHandles();

    if (!params.principal.empty())
    {
        std::cout << "GSSInitiatorContext::initHandles principal " << params.principal << std::endl;
        if (!params.realm.empty())
            throw KerberosError("Realm and principal name cannot be specified simultaneously");

        gss_buffer_desc initiator_name_buf;
        initiator_name_buf.length = params.principal.size();
        initiator_name_buf.value = const_cast<char *>(params.principal.c_str());

        /* gss_name_t */ initiator_name = GSS_C_NO_NAME;

        // SCOPE_EXIT({
        //     if (initiator_name != GSS_C_NO_NAME)
        //     {
        //         OM_uint32 minor_status = 0;
        //         [[maybe_unused]] OM_uint32 major_status = gss_release_name(
        //             &minor_status,
        //             &initiator_name
        //         );
        //         initiator_name = GSS_C_NO_NAME;
        //     }
        // });

        OM_uint32 minor_status = 0;
        OM_uint32 major_status = gss_import_name(
            &minor_status,
            &initiator_name_buf,
            (gss_OID) gss_nt_user_name /* GSS_C_NT_HOSTBASED_SERVICE */,
            &initiator_name
        );

        if (GSS_ERROR(major_status))
        {
            const auto messages = extractStatusMessages(major_status, minor_status, GSS_C_NO_OID);
            if (initiator_name != GSS_C_NO_NAME)
            {
                OM_uint32 minor_status = 0;
                [[maybe_unused]] OM_uint32 major_status = gss_release_name(
                    &minor_status,
                    &initiator_name
                );
                initiator_name = GSS_C_NO_NAME;
            }
            std::cout << "GSSInitiatorContext::initHandles gss_import_name: error " << messages << std::endl;
            throw KerberosError("gss_import_name() failed" + (messages.empty() ? "" : ": " + messages));
        }



        gss_buffer_desc target_name_buf;
        target_name_buf.length = params.target.size();
        target_name_buf.value = const_cast<char *>(params.target.c_str());
        minor_status = 0;
        major_status = gss_import_name(
            &minor_status,
            &target_name_buf,
            (gss_OID) gss_nt_user_name /* GSS_C_NT_HOSTBASED_SERVICE */,
            &target_name
        );

        if (GSS_ERROR(major_status))
        {
            const auto messages = extractStatusMessages(major_status, minor_status, GSS_C_NO_OID);
            if (target_name != GSS_C_NO_NAME)
            {
                OM_uint32 minor_status = 0;
                [[maybe_unused]] OM_uint32 major_status = gss_release_name(
                    &minor_status,
                    &target_name
                );
                target_name = GSS_C_NO_NAME;
            }
            std::cout << "GSSInitiatorContext::initHandles gss_import_name (target): error " << messages << std::endl;
            throw KerberosError("gss_import_name() failed" + (messages.empty() ? "" : ": " + messages));
        }




        gss_OID_set_desc mechs, *mechsp = GSS_C_NO_OID_SET;
        mechs.elements = GSS_C_NULL_OID;
        mechs.count = 1;
        mechsp = &mechs;


        std::cout << "GSSInitiatorContext::initHandles initiator_name_buf.value " << reinterpret_cast<char*>(initiator_name_buf.value) << std::endl;

        minor_status = 0;
        major_status = gss_acquire_cred(
            &minor_status,
            initiator_name,
            0 /*GSS_C_INDEFINITE*/,
            mechsp /*GSS_C_NO_OID_SET*/,
            // GSS_C_ACCEPT,
            GSS_C_INITIATE,
            &initiator_credentials_handle,
            nullptr,
            nullptr
        );

        if (GSS_ERROR(major_status))
        {
            const auto messages = extractStatusMessages(major_status, minor_status, GSS_C_NO_OID);
            if (initiator_name != GSS_C_NO_NAME)
            {
                OM_uint32 minor_status = 0;
                [[maybe_unused]] OM_uint32 major_status = gss_release_name(
                    &minor_status,
                    &initiator_name
                );
                initiator_name = GSS_C_NO_NAME;
            }
            std::cout << "GSSInitiatorContext::initHandles gss_acquire_cred: error " << messages << std::endl;
            throw KerberosError("gss_acquire_cred() failed" + (messages.empty() ? "" : ": " + messages));
        }
        // if (initiator_name != GSS_C_NO_NAME)
        // {
        //     OM_uint32 minor_status = 0;
        //     [[maybe_unused]] OM_uint32 major_status = gss_release_name(
        //         &minor_status,
        //         &initiator_name
        //     );
        //     initiator_name = GSS_C_NO_NAME;
        // }
    }
}

std::string GSSInitiatorContext::processToken(const std::string & input_token)
{
    std::scoped_lock lock(gss_global_mutex);

    std::cout << "top of GSSInitiatorContext::processToken" << std::endl;

    std::string output_token;

    try
    {
        if (is_ready || is_failed || *context_handle == GSS_C_NO_CONTEXT)
            reset();

        std::cout << "GSSInitiatorContext::processToken: after reset" << std::endl;
        gss_buffer_desc input_token_buf;
        input_token_buf.length = input_token.size();
        input_token_buf.value = const_cast<char *>(input_token.c_str());

        gss_buffer_desc output_token_buf;
        output_token_buf.length = 0;
        output_token_buf.value = nullptr;

        // gss_name_t initiator_name = GSS_C_NO_NAME;
        gss_OID actual_mech_type;



        OM_uint32 flags = 0;
        OM_uint32 ret_flags = 0;

        // SCOPE_EXIT({
        //     if (initiator_name != GSS_C_NO_NAME)
        //     {
        //         OM_uint32 minor_status = 0;
        //         [[maybe_unused]] OM_uint32 major_status = gss_release_name(
        //             &minor_status,
        //             &initiator_name
        //         );
        //         initiator_name = GSS_C_NO_NAME;
        //     }

        //     OM_uint32 minor_status = 0;
        //     [[maybe_unused]] OM_uint32 major_status = gss_release_buffer(
        //         &minor_status,
        //         &output_token_buf
        //     );
        // });

        OM_uint32 minor_status = 0;
        // OM_uint32 major_status = gss_accept_sec_context(
        //     &minor_status,
        //     &context_handle,
        //     initiator_credentials_handle,
        //     &input_token_buf,
        //     GSS_C_NO_CHANNEL_BINDINGS,
        //     &initiator_name,
        //     &mech_type,
        //     &output_token_buf,
        //     &flags,
        //     nullptr,
        //     nullptr
        // );

        std::cout << "GSSInitiatorContext::processToken: before gss_init_sec_context" << std::endl;
        OM_uint32 major_status = gss_init_sec_context(
          &minor_status,
          initiator_credentials_handle,
          /* & */context_handle,


          target_name,  /* initiator_name, */


          nullptr, /* input mech type*/
          flags,  /* ret_flags */
          0,   /* time_req */
          nullptr /*GSS_C_NO_CHANNEL_BINDINGS*/, /* input_chan_bindings */
          &input_token_buf,
          &actual_mech_type,   /* actual_mech_type */
          &output_token_buf,
          &ret_flags,  /* ret_flags */
          nullptr /* time_rec */
        );

        if (major_status == GSS_S_COMPLETE)
        {
            std::cout << "GSSInitiatorContext::processToken: GSS_S_COMPLETE" << std::endl;
            if (!params.mechanism.empty() && !equalMechanisms(params.mechanism, actual_mech_type))
            {
                std::cout << "gss_accept_sec_context() succeeded, but: the authentication mechanism is not what was expected" << std::endl;

                throw KerberosError("gss_accept_sec_context() succeeded, but: the authentication mechanism is not what was expected");
            }


            if (flags & GSS_C_ANON_FLAG)
            {
                std::cout << "gss_accept_sec_context() succeeded, but: the initiator does not wish to be authenticated" << std::endl;
                throw KerberosError("gss_accept_sec_context() succeeded, but: the initiator does not wish to be authenticated");
            }

            std::tie(user_name, realm) = extractNameAndRealm(initiator_name);


            // major_status = gss_release_name(
            //     &minor_status,
            //     &initiator_name
            // );
            // initiator_name = GSS_C_NO_NAME;




            // if (user_name.empty())
            //     throw KerberosError("gss_accept_sec_context() succeeded, but: the initiator name cannot be extracted");

            // if (realm.empty())
            //     throw KerberosError("gss_accept_sec_context() succeeded, but: the initiator realm cannot be extracted");

            // if (!params.realm.empty() && params.realm != realm)
            //     throw KerberosError("gss_accept_sec_context() succeeded, but: the initiator realm is not what was expected (expected: " + params.realm + ", actual: " + realm + ")");

            output_token = bufferToString(output_token_buf);

            major_status = gss_release_buffer(
                &minor_status,
                &output_token_buf
            );

            is_ready = true;
            is_failed = false;

            // resetHandles();
        }
        else if (!GSS_ERROR(major_status) && (major_status & GSS_S_CONTINUE_NEEDED))
        {
            std::cout << "GSSInitiatorContext::processToken: GSS_S_CONTINUE_NEEDED" << std::endl;
            output_token = bufferToString(output_token_buf);

            is_ready = false;
            is_failed = false;
        }
        else
        {
            const auto messages = extractStatusMessages(major_status, minor_status, actual_mech_type);
            std::cout << "GSSInitiatorContext::processToken: error " << messages << std::endl;
            throw KerberosError("gss_accept_sec_context() failed" + (messages.empty() ? "" : ": " + messages));
        }
    }
    catch (...)
    {
        // tryLogCurrentException(log, "Could not process GSS token");
        std::cout << "GSSInitiatorContext::processToken: catch(...)" << std::endl;

        is_ready = true;
        is_failed = true;

        resetHandles();
    }

    return output_token;
}

#else // WITH_GSSAPI

void GSSInitiatorContext::reset()
{
}

void GSSInitiatorContext::resetHandles() noexcept
{
}

void GSSInitiatorContext::initHandles()
{
}

std::string GSSInitiatorContext::processToken(const std::string &)
{
    throw KerberosError("clickhouse-cpp was built without GSS-API/Kerberos support");
}

#endif // WITH_GSSAPI

}
