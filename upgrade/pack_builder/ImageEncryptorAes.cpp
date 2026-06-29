#include "upgrade/pack_builder/ImageEncryptorAes.hpp"
#include <psa/crypto.h>
#include <algorithm>
#include <array>
#include <cassert>

extern "C"
{
#include "crypto/tiny-aes128/TinyAes.h"
}

namespace application
{
    ImageEncryptorAes::ImageEncryptorAes(hal::SynchronousRandomDataGenerator& randomDataGenerator, infra::ConstByteRange key)
        : randomDataGenerator(randomDataGenerator)
        , key(key)
    {}

    uint32_t ImageEncryptorAes::EncryptionAndMacMethod() const
    {
        return encryptionAndMacMethod;
    }

    std::vector<uint8_t> ImageEncryptorAes::Secure(const std::vector<uint8_t>& data) const
    {
        std::vector<uint8_t> counter(blockLength, 0);
        randomDataGenerator.GenerateRandomData(counter);

        if (psa_crypto_init() != PSA_SUCCESS)
            throw std::runtime_error("PSA Crypto initialization failed");

        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
        psa_set_key_algorithm(&attributes, PSA_ALG_CTR);
        psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
        psa_set_key_bits(&attributes, 128);

        psa_key_id_t keyId;
        psa_status_t status = psa_import_key(&attributes, key.begin(), key.size(), &keyId);
        psa_reset_key_attributes(&attributes);
        if (status != PSA_SUCCESS)
            throw std::runtime_error("Key import failed");

        std::vector<uint8_t> result = counter;
        result.resize(result.size() + data.size(), 0);

        size_t outputLen = 0;
        status = psa_cipher_encrypt(
            keyId,
            PSA_ALG_CTR,
            counter.data(), counter.size(),
            data.data(), data.size(),
            result.data() + blockLength, result.size() - blockLength,
            &outputLen
        );

        psa_destroy_key(keyId);

        if (status != PSA_SUCCESS)
            throw std::runtime_error("AES encryption failed");

        if (!CheckDecryption(data, result))
            throw std::runtime_error("AES decryption check failed");

        return result;
    }

    bool ImageEncryptorAes::CheckDecryption(const std::vector<uint8_t>& original, const std::vector<uint8_t>& encrypted) const
    {
        std::vector<uint8_t> counter(encrypted.begin(), encrypted.begin() + blockLength);
        std::vector<uint8_t> currentStreamBlock(counter.size(), 0);
        std::size_t currentStreamBlockOffset = currentStreamBlock.size();

        std::vector<uint8_t> decrypted(encrypted.begin() + blockLength, encrypted.end());
        infra::ByteRange data(decrypted.data(), decrypted.data() + decrypted.size());
        while (!data.empty())
        {
            if (currentStreamBlockOffset == currentStreamBlock.size())
            {
                AES128_ECB_encrypt(counter.data(), key.begin(), currentStreamBlock.data());
                currentStreamBlockOffset = 0;

                for (std::size_t i = counter.size(); i != 0; --i)
                    if (++counter[i - 1] != 0)
                        break;
            }

            data.front() ^= currentStreamBlock[currentStreamBlockOffset];
            data.pop_front();
            ++currentStreamBlockOffset;
        }

        return mbedtls_aes_self_test(0) == 0 && decrypted == original;
    }
}
