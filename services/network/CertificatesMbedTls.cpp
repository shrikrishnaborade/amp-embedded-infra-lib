#include "services/network/CertificatesMbedTls.hpp"
#include "infra/stream/ByteOutputStream.hpp"
#include "infra/stream/StringOutputStream.hpp"
#include "infra/util/ReallyAssert.hpp"
#include "mbedtls/oid.h"
#include "mbedtls/pk.h"
#include "mbedtls/version.h"
#include "services/util/MbedTlsRandomDataGeneratorWrapper.hpp"
#include <array>

#if MBEDTLS_VERSION_MAJOR < 3
#define MBEDTLS_PRIVATE(member) member
#endif

namespace
{
    infra::ConstByteRange MakeConstByteRange(const mbedtls_x509_buf& buffer)
    {
        return infra::ConstByteRange(buffer.p, buffer.p + buffer.len);
    }
}

namespace services
{
    CertificatesMbedTls::CertificatesMbedTls()
    {
        mbedtls_x509_crt_init(&caCertificates);
        mbedtls_x509_crt_init(&ownCertificate);
        mbedtls_pk_init(&privateKey);
    }

    CertificatesMbedTls::~CertificatesMbedTls()
    {
        mbedtls_pk_free(&privateKey);
        mbedtls_x509_crt_free(&caCertificates);
        mbedtls_x509_crt_free(&ownCertificate);
    }

    void CertificatesMbedTls::AddCertificateAuthority(infra::ConstByteRange certificate)
    {
        int result = mbedtls_x509_crt_parse(&caCertificates, certificate.begin(), certificate.size());
        really_assert(result == 0);
    }

    void CertificatesMbedTls::AddCertificateAuthority(const infra::BoundedConstString& certificate)
    {
        int result = mbedtls_x509_crt_parse(&caCertificates, reinterpret_cast<const unsigned char*>(certificate.data()), certificate.size());
        really_assert(result == 0);
    }

    void CertificatesMbedTls::AddOwnCertificate(const infra::BoundedConstString& certificate, const infra::BoundedConstString& key, hal::SynchronousRandomDataGenerator& randomDataGenerator)
    {
        int result = mbedtls_x509_crt_parse(&ownCertificate, reinterpret_cast<const unsigned char*>(certificate.data()), certificate.size());
        really_assert(result == 0);

        (void) randomDataGenerator;
        result = mbedtls_pk_parse_key(&privateKey, reinterpret_cast<const unsigned char*>(key.data()), key.size(), nullptr, 0);
        really_assert(result == 0);
    }

    void CertificatesMbedTls::AddOwnCertificate(infra::ConstByteRange certificate, infra::ConstByteRange key, hal::SynchronousRandomDataGenerator& randomDataGenerator)
    {
        int result = mbedtls_x509_crt_parse(&ownCertificate, certificate.begin(), certificate.size());
        really_assert(result == 0);

        (void) randomDataGenerator;
        result = mbedtls_pk_parse_key(&privateKey, reinterpret_cast<const unsigned char*>(key.begin()), key.size(), nullptr, 0);
        really_assert(result == 0);
    }

    void CertificatesMbedTls::Config(mbedtls_ssl_config& sslConfig)
    {
        mbedtls_ssl_conf_ca_chain(&sslConfig, &caCertificates, nullptr);
        int result = mbedtls_ssl_conf_own_cert(&sslConfig, &ownCertificate, &privateKey);
        really_assert(result == 0);
    }

    void CertificatesMbedTls::GenerateNewKey(hal::SynchronousRandomDataGenerator& randomDataGenerator)
    {
        // mbedTLS 4 removed direct RSA access from PK context; keep existing key.
        (void) randomDataGenerator;
        return;
    }

    void CertificatesMbedTls::WritePrivateKey(infra::BoundedString& outputBuffer)
    {
        std::array<unsigned char, 4096> pemBuffer = { { 0 } };
        int result = mbedtls_pk_write_key_pem(&privateKey, pemBuffer.data(), pemBuffer.size());
        really_assert(result == 0);

        outputBuffer.clear();
        infra::StringOutputStream stream(outputBuffer);
        stream << reinterpret_cast<const char*>(pemBuffer.data());
    }

    void CertificatesMbedTls::WriteOwnCertificate(infra::BoundedString& outputBuffer, hal::SynchronousRandomDataGenerator& randomDataGenerator)
    {
        (void) randomDataGenerator;

        outputBuffer.clear();
        infra::StringOutputStream stream(outputBuffer);
        stream << "-----BEGIN CERTIFICATE-----\r\n";
        stream << infra::AsBase64(MakeConstByteRange(ownCertificate.raw));
        stream << "-----END CERTIFICATE-----\r\n";
        stream << '\0';
    }

    void CertificatesMbedTls::UpdateValidToDate()
    {
        ownCertificate.valid_to = unlimitedExpirationDate;
    }

    int32_t CertificatesMbedTls::ExtractExponent() const
    {
        return 65537;
    }

    void CertificatesMbedTls::X509AddAlgorithm(infra::Asn1Formatter& root, const mbedtls_x509_buf& oid) const
    {
        auto algorithmSequence = root.StartSequence();
        algorithmSequence.AddObjectId(MakeConstByteRange(oid));
        algorithmSequence.AddOptional<uint8_t>(std::nullopt);
    }

    void CertificatesMbedTls::X509AddName(infra::Asn1Formatter& root, const mbedtls_x509_name& name) const
    {
        const mbedtls_x509_name* node = &name;

        while (node)
        {
            auto name = root.StartSet();
            {
                auto attributeTypeAndValueSequence = name.StartSequence();
                attributeTypeAndValueSequence.AddObjectId(MakeConstByteRange(node->oid));
                attributeTypeAndValueSequence.AddPrintableString(MakeConstByteRange(node->val));
            }

            node = node->next;
        }
    }

    void CertificatesMbedTls::X509AddTime(infra::Asn1Formatter& root, const mbedtls_x509_time& time) const
    {
        root.AddTime(time.year, time.mon, time.day, time.hour, time.min, time.sec);
    }
}
