#include "upgrade/boot_loader/DecryptorAesMbedTls.hpp"

namespace application
{
    DecryptorAesMbedTls::DecryptorAesMbedTls(infra::ConstByteRange key)
        : currentStreamBlock()
        , counter()
    {
        psa_crypto_init();

        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
        psa_set_key_algorithm(&attributes, PSA_ALG_CTR);
        psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
        psa_set_key_bits(&attributes, 128);

        psa_import_key(&attributes, key.begin(), key.size(), &keyId);
        psa_reset_key_attributes(&attributes);
    }

    infra::ByteRange DecryptorAesMbedTls::StateBuffer()
    {
        return infra::MakeByteRange(counter);
    }

    void DecryptorAesMbedTls::Reset()
    {
        currentStreamBlockOffset = 0;
    }

    void DecryptorAesMbedTls::DecryptPart(infra::ByteRange data)
    {
        size_t outputLen = 0;
        psa_cipher_encrypt(
            keyId,
            PSA_ALG_CTR,
            counter.data(), counter.size(),
            data.begin(), data.size(),
            data.begin(), data.size(),
            &outputLen
        );
    }

    bool DecryptorAesMbedTls::DecryptAndAuthenticate(infra::ByteRange data)
    {
        DecryptPart(data);

        return true;
    }
}
