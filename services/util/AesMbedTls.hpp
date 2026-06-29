#ifndef SERVICES_AES_MBEDTLS_HPP
#define SERVICES_AES_MBEDTLS_HPP

// ESP-IDF mbedtls 4.x moved AES to private API; include directly
#ifndef MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#endif
#include "mbedtls/private/aes.h"
#include "services/util/Aes.hpp"

namespace services
{
    class Aes128CtrMbedTls
        : public Aes128Ctr
    {
    public:
        Aes128CtrMbedTls();

        void SetKey(const std::array<uint8_t, 16>& key) override;
        void Encrypt(std::array<uint8_t, 16>& counter, infra::ConstByteRange input, infra::ByteRange output) override;

    private:
        mbedtls_aes_context context;
    };
}

#endif
