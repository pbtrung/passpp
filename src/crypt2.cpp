// Multiple Encryption

#include <iostream>
#include <string>

#include <cryptopp/files.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/kalyna.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha3.h>
#include <cryptopp/threefish.h>
using namespace CryptoPP;

SecByteBlock read_key(char *keyf);
void encrypt(SecByteBlock key);
void decrypt(SecByteBlock key);

const unsigned int KEY_FILE_SIZE = 1024;

const unsigned int T3F_TWEAK_SIZE = 16;
const unsigned int T3F_KEY_SIZE = 128;
const unsigned int T3F_IV_SIZE = 128;

const unsigned int KLN_KEY_SIZE = 64;
const unsigned int KLN_IV_SIZE = 64;

const unsigned int SALT_SIZE = 64;
const unsigned int INFO_SIZE = 64;
const unsigned int HMAC_KEY_SIZE = 64;
const unsigned int HMAC_SIZE = 64;

const unsigned int HKDF_SIZE = T3F_TWEAK_SIZE + T3F_KEY_SIZE + T3F_IV_SIZE +
                               KLN_KEY_SIZE + KLN_IV_SIZE + HMAC_KEY_SIZE * 2;

int main(int argc, char *argv[]) {

    SecByteBlock key;
    if (argc == 4 &&
        (strcmp(argv[1], "-e") == 0 || strcmp(argv[1], "-d") == 0) &&
        strcmp(argv[2], "-k") == 0) {
        key = read_key(argv[3]);

    } else {
        std::cerr << "Wrong arguments" << std::endl;
        return -1;
    }

    if (strcmp(argv[1], "-e") == 0) {
        encrypt(key);
    } else if (strcmp(argv[1], "-d") == 0) {
        decrypt(key);
    }

    return 0;
}

SecByteBlock read_key(char *keyf) {
    try {
        SecByteBlock key(KEY_FILE_SIZE);
        FileSource fsource(keyf, false);
        fsource.Attach(new ArraySink(key, key.size()));
        fsource.Pump(key.size());
        return key;
    } catch (const Exception &ex) {
        std::cerr << ex.what() << std::endl;
        exit(-2);
    }
}

void encrypt(SecByteBlock key) {
    try {
        SecByteBlock hkdf_hash(HKDF_SIZE), salt(SALT_SIZE), info(INFO_SIZE),
            salt_info_hmac(HMAC_SIZE);

        OS_GenerateRandomBlock(false, salt, salt.size());
        OS_GenerateRandomBlock(false, info, info.size());
        HKDF<SHA3_512> hkdf;
        hkdf.DeriveKey(hkdf_hash, hkdf_hash.size(), key, key.size(), salt,
                       salt.size(), info, info.size());

        ConstByteArrayParameter twk(&hkdf_hash[0], T3F_TWEAK_SIZE, false);
        AlgorithmParameters t3f_params = MakeParameters(Name::Tweak(), twk);
        Threefish1024::Encryption t3f(&hkdf_hash[T3F_TWEAK_SIZE], T3F_KEY_SIZE);
        t3f.SetTweak(t3f_params);
        CBC_CTS_Mode_ExternalCipher::Encryption t3f_enc(
            t3f, &hkdf_hash[T3F_TWEAK_SIZE + T3F_KEY_SIZE]);

        Kalyna512::Encryption kln(
            &hkdf_hash[T3F_TWEAK_SIZE + T3F_KEY_SIZE + T3F_IV_SIZE],
            KLN_KEY_SIZE);
        CBC_CTS_Mode_ExternalCipher::Encryption kln_enc(
            kln, &hkdf_hash[T3F_TWEAK_SIZE + T3F_KEY_SIZE + T3F_IV_SIZE +
                            KLN_KEY_SIZE]);

        StreamTransformationFilter t3f_ef(t3f_enc);
        StreamTransformationFilter kln_ef(kln_enc);

        FileSink fsnk(std::cout);

        HMAC<SHA3_512> hmac_salt_info;
        hmac_salt_info.SetKey(
            &hkdf_hash[T3F_TWEAK_SIZE + T3F_KEY_SIZE + T3F_IV_SIZE +
                       KLN_KEY_SIZE + KLN_IV_SIZE],
            HMAC_KEY_SIZE);
        hmac_salt_info.Update(salt, salt.size());
        hmac_salt_info.Update(info, info.size());
        hmac_salt_info.Final(salt_info_hmac);

        HMAC<SHA3_512> hmac;
        hmac.SetKey(&hkdf_hash[T3F_TWEAK_SIZE + T3F_KEY_SIZE + T3F_IV_SIZE +
                               KLN_KEY_SIZE + KLN_IV_SIZE + HMAC_KEY_SIZE],
                    HMAC_KEY_SIZE);

        HashFilter hf(hmac, new Redirector(fsnk), true);
        t3f_ef.Attach(new Redirector(hf));
        kln_ef.Attach(new Redirector(t3f_ef));

        fsnk.Put(salt, salt.size());
        fsnk.Put(info, info.size());
        fsnk.Put(salt_info_hmac, salt_info_hmac.size());
        FileSource fsrc(std::cin, true, new Redirector(kln_ef));

    } catch (const Exception &ex) {
        std::cerr << ex.what() << std::endl;
        exit(-3);
    }
}

void decrypt(SecByteBlock key) {
    try {
        SecByteBlock hkdf_hash(HKDF_SIZE), salt(SALT_SIZE), info(INFO_SIZE),
            salt_info_hmac(HMAC_SIZE);

        FileSource fsrc(std::cin, false);
        FileSink fsnk(std::cout);

        fsrc.Attach(new ArraySink(salt, salt.size()));
        fsrc.Pump(salt.size());
        fsrc.Attach(new ArraySink(info, info.size()));
        fsrc.Pump(info.size());
        fsrc.Detach(new ArraySink(salt_info_hmac, salt_info_hmac.size()));
        fsrc.Pump(salt_info_hmac.size());

        HKDF<SHA3_512> hkdf;
        hkdf.DeriveKey(hkdf_hash, hkdf_hash.size(), key, key.size(), salt,
                       salt.size(), info, info.size());

        SecByteBlock auth_salt_info_hmac(HMAC_SIZE);
        HMAC<SHA3_512> hmac_salt_info;
        hmac_salt_info.SetKey(
            &hkdf_hash[T3F_TWEAK_SIZE + T3F_KEY_SIZE + T3F_IV_SIZE +
                       KLN_KEY_SIZE + KLN_IV_SIZE],
            HMAC_KEY_SIZE);
        hmac_salt_info.Update(salt, salt.size());
        hmac_salt_info.Update(info, info.size());
        hmac_salt_info.Final(auth_salt_info_hmac);
        if (!VerifyBufsEqual(auth_salt_info_hmac, salt_info_hmac, HMAC_SIZE)) {
            std::cerr << "decrypt: Unable to verify salt and info" << std::endl;
            exit(-4);
        }

        ConstByteArrayParameter twk(&hkdf_hash[0], T3F_TWEAK_SIZE, false);
        AlgorithmParameters params = MakeParameters(Name::Tweak(), twk);
        Threefish1024::Decryption t3f(&hkdf_hash[T3F_TWEAK_SIZE], T3F_KEY_SIZE);
        t3f.SetTweak(params);
        CBC_CTS_Mode_ExternalCipher::Decryption t3f_dec(
            t3f, &hkdf_hash[T3F_TWEAK_SIZE + T3F_KEY_SIZE]);

        Kalyna512::Decryption kln(
            &hkdf_hash[T3F_TWEAK_SIZE + T3F_KEY_SIZE + T3F_IV_SIZE],
            KLN_KEY_SIZE);
        CBC_CTS_Mode_ExternalCipher::Decryption kln_dec(
            kln, &hkdf_hash[T3F_TWEAK_SIZE + T3F_KEY_SIZE + T3F_IV_SIZE +
                            KLN_KEY_SIZE]);

        StreamTransformationFilter t3f_df(t3f_dec);
        StreamTransformationFilter kln_df(kln_dec);

        HMAC<SHA3_512> hmac;
        hmac.SetKey(&hkdf_hash[T3F_TWEAK_SIZE + T3F_KEY_SIZE + T3F_IV_SIZE +
                               KLN_KEY_SIZE + KLN_IV_SIZE + HMAC_KEY_SIZE],
                    HMAC_KEY_SIZE);
        const int flags = HashVerificationFilter::THROW_EXCEPTION |
                          HashVerificationFilter::HASH_AT_END |
                          HashVerificationFilter::PUT_MESSAGE;
        HashVerificationFilter hf(hmac, new Redirector(t3f_df), flags);
        fsrc.Attach(new Redirector(hf));
        kln_df.Attach(new Redirector(fsnk));
        t3f_df.Attach(new Redirector(kln_df));
        fsrc.PumpAll();

    } catch (const Exception &ex) {
        std::cerr << ex.what() << std::endl;
        exit(-4);
    }
}