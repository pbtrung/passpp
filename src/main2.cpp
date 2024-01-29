#include <fstream>
#include <iostream>

#include <cryptopp/base32.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/kalyna.h>
#include <cryptopp/misc.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha3.h>
#include <cryptopp/threefish.h>
using namespace CryptoPP;

#include "json.hpp"
using json = nlohmann::json;

const unsigned int KEY_SIZE = 1024;
const unsigned int TWEAK_SIZE = 16;
const unsigned int HASH_KEY_SIZE = 64;
const unsigned int HASH_SIZE = 64;
const unsigned int SALT_SIZE = 64;
const unsigned int T3F_IV_SIZE = 128;
const unsigned int T3F_KEY_SIZE = 128;
const unsigned int T3F_BLOCK_SIZE = 128;
const unsigned int PASS_LEN = 20;
const unsigned int KLN_KEY_SIZE = 64;
const unsigned int KLN_IV_SIZE = 64;
const unsigned int HKDF_SIZE = T3F_KEY_SIZE + T3F_IV_SIZE + TWEAK_SIZE +
                               HASH_KEY_SIZE + KLN_KEY_SIZE + KLN_IV_SIZE;

int truncate(SecByteBlock hmac, int digits) {
    int offset = hmac[hmac.size() - 1] & 0x0f;

    int bin_code =
        ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) | ((hmac[offset + 3] & 0xff));

    long long int DIGITS_POWER[] = {1,         10,         100,        1000,
                                    10000,     100000,     1000000,    10000000,
                                    100000000, 1000000000, 10000000000};
    int token = (int)(bin_code % DIGITS_POWER[digits]);
    return token;
}

SecByteBlock finalize(int digits, int tk) {
    SecByteBlock token(digits + 1);
    char fmt[6];
    sprintf(fmt, "%%0%dd", digits);
    snprintf((char *)token.data(), digits + 1, fmt, tk);
    return token;
}

std::string normalize_secret(SecByteBlock K) {
    std::string j =
        std::string(reinterpret_cast<const char *>(K.data()), K.size());
    j.erase(std::remove_if(j.begin(), j.end(), isspace), j.end());
    std::transform(j.begin(), j.end(), j.begin(), ::toupper);
    return j;
}

SecByteBlock compute_hmac(SecByteBlock K, uint64_t counter, int algo) {
    std::string normalized_K = normalize_secret(K);

    size_t key_size = (size_t)((normalized_K.size() + 1.6 - 1) / 1.6);

    int lookup[256];
    const byte ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    Base64Decoder::InitializeDecodingLookupArray(lookup, ALPHABET, 32, true);
    Base32Decoder decoder;
    AlgorithmParameters params =
        MakeParameters(Name::DecodingLookupArray(), (const int *)lookup);
    decoder.IsolatedInitialize(params);

    SecByteBlock key(key_size);
    decoder.Attach(new ArraySink(key, key.size()));
    decoder.Put((byte *)normalized_K.data(), normalized_K.size());
    decoder.MessageEnd();

    const size_t counter_byte_size = sizeof(counter);
    byte counter_byte[counter_byte_size];
    // Big-endian representation
    for (size_t i = 0; i < counter_byte_size; ++i) {
        counter_byte[counter_byte_size - 1 - i] =
            static_cast<byte>((counter >> (8 * i)) & 0xFF);
    }

    SecByteBlock mac;
    if (algo == 1) {
        mac.CleanNew(HMAC<CryptoPP::SHA1>::DIGESTSIZE);
        HMAC<CryptoPP::SHA1> h1(key, key.size());
        h1.Update(counter_byte, counter_byte_size);
        h1.Final(mac);
    } else if (algo == 2) {
        mac.CleanNew(HMAC<CryptoPP::SHA256>::DIGESTSIZE);
        HMAC<CryptoPP::SHA256> h256(key, key.size());
        h256.Update(counter_byte, counter_byte_size);
        h256.Final(mac);
    } else if (algo == 3) {
        mac.CleanNew(HMAC<CryptoPP::SHA512>::DIGESTSIZE);
        HMAC<CryptoPP::SHA512> h512(key, key.size());
        h512.Update(counter_byte, counter_byte_size);
        h512.Final(mac);
    }

    return mac;
}

SecByteBlock get_hotp(SecByteBlock secret, uint64_t counter, int digits,
                      int algo) {
    SecByteBlock hmac = compute_hmac(secret, counter, algo);
    int tk = truncate(hmac, digits);
    return finalize(digits, tk);
}

SecByteBlock get_totp_at(SecByteBlock secret, uint64_t current_time, int digits,
                         int period, int algo) {
    uint64_t counter = current_time / period;
    SecByteBlock totp = get_hotp(secret, counter, digits, algo);
    return totp;
}

SecByteBlock get_totp(SecByteBlock secret, int digits, int period, int algo) {
    uint64_t current_time = static_cast<uint64_t>(std::time(nullptr));
    return get_totp_at(secret, current_time, digits, period, algo);
}

static void error_exit(std::string msg) {
    std::cerr << msg << std::endl;
    exit(-1);
}

size_t get_file_size(std::ifstream *stream) {
    std::ifstream::pos_type old = stream->tellg();
    std::ifstream::pos_type end = stream->seekg(0, std::ios_base::end).tellg();
    stream->seekg(old);

    return static_cast<size_t>(end);
}

SecByteBlock read_key(char *keyf) {
    std::ifstream infile(keyf, std::ios::in | std::ios::binary);
    if (get_file_size(&infile) != KEY_SIZE) {
        error_exit("[read_key] Wrong key file");
    }
    SecByteBlock key(KEY_SIZE);
    infile.read((char *)key.data(), key.size());
    infile.close();
    return key;
}

SecByteBlock read_file(char *f) {
    std::ifstream infile(f, std::ios::in | std::ios::binary);
    SecByteBlock file(get_file_size(&infile));
    infile.read((char *)file.data(), file.size());
    infile.close();
    return file;
}

SecByteBlock encrypt(SecByteBlock data, SecByteBlock key) {
    SecByteBlock buf(HASH_SIZE + SALT_SIZE + data.size() * 2);
    SecByteBlock pad(data.size());
    OS_GenerateRandomBlock(false, &buf[HASH_SIZE], SALT_SIZE);
    OS_GenerateRandomBlock(false, pad, pad.size());

    SecByteBlock hkdf_hash(HKDF_SIZE);
    HKDF<SHA3_512> hkdf;
    hkdf.DeriveKey(hkdf_hash, hkdf_hash.size(), key, key.size(),
                   &buf[HASH_SIZE], SALT_SIZE, NULL, 0);

    xorbuf(data, pad, pad.size());

    Kalyna512::Encryption kln(
        &hkdf_hash[T3F_KEY_SIZE + T3F_IV_SIZE + TWEAK_SIZE + HASH_KEY_SIZE],
        KLN_KEY_SIZE);
    CBC_CTS_Mode_ExternalCipher::Encryption kln_enc(
        kln, &hkdf_hash[T3F_KEY_SIZE + T3F_IV_SIZE + TWEAK_SIZE +
                        HASH_KEY_SIZE + KLN_KEY_SIZE]);

    StreamTransformationFilter kln_stf(
        kln_enc,
        new ArraySink(&buf[HASH_SIZE + SALT_SIZE + data.size()], data.size()));
    kln_stf.Put(pad, pad.size());
    kln_stf.MessageEnd();

    ConstByteArrayParameter twk(&hkdf_hash[T3F_KEY_SIZE + T3F_IV_SIZE],
                                TWEAK_SIZE, false);
    AlgorithmParameters params = MakeParameters(Name::Tweak(), twk);
    Threefish1024::Encryption t3f(&hkdf_hash[0], T3F_KEY_SIZE);
    t3f.SetTweak(params);
    CBC_CTS_Mode_ExternalCipher::Encryption enc(t3f, &hkdf_hash[T3F_KEY_SIZE]);

    StreamTransformationFilter stf(
        enc, new ArraySink(&buf[HASH_SIZE + SALT_SIZE], data.size()));
    stf.Put(data, data.size());
    stf.MessageEnd();

    SecByteBlock hmac_hash(HASH_SIZE);
    HMAC<SHA3_512> hmac;
    hmac.SetKey(&hkdf_hash[T3F_KEY_SIZE + T3F_IV_SIZE + TWEAK_SIZE],
                HASH_KEY_SIZE);
    hmac.Update(&buf[HASH_SIZE], SALT_SIZE + data.size() * 2);
    hmac.Final(hmac_hash);
    std::memcpy(&buf[0], hmac_hash, HASH_SIZE);

    return buf;
}

void encrypt_file(char *keyf, char *inf, char *outf) {
    SecByteBlock key = read_key(keyf);
    SecByteBlock file = read_file(inf);

    SecByteBlock buf = encrypt(file, key);
    FileSink fsnk(outf);
    fsnk.Put(buf, buf.size());
}

SecByteBlock decrypt(SecByteBlock data, SecByteBlock key) {
    SecByteBlock buf((data.size() - HASH_SIZE - SALT_SIZE) / 2);
    SecByteBlock pad(buf.size());

    SecByteBlock hkdf_hash(HKDF_SIZE);
    HKDF<SHA3_512> hkdf;
    hkdf.DeriveKey(hkdf_hash, hkdf_hash.size(), key, key.size(),
                   &data[HASH_SIZE], SALT_SIZE, NULL, 0);

    SecByteBlock hmac_hash(HASH_SIZE);
    HMAC<SHA3_512> hmac;
    hmac.SetKey(&hkdf_hash[T3F_KEY_SIZE + T3F_IV_SIZE + TWEAK_SIZE],
                HASH_KEY_SIZE);
    hmac.Update(&data[HASH_SIZE], data.size() - HASH_SIZE);
    hmac.Final(hmac_hash);
    SecByteBlock hash(HASH_SIZE);
    std::memcpy(hash, &data[0], HASH_SIZE);
    if (hash != hmac_hash) {
        error_exit("[decrypt] Wrong HMAC");
    }

    ConstByteArrayParameter twk(&hkdf_hash[T3F_KEY_SIZE + T3F_IV_SIZE],
                                TWEAK_SIZE, false);
    AlgorithmParameters params = MakeParameters(Name::Tweak(), twk);
    Threefish1024::Decryption t3f(&hkdf_hash[0], T3F_KEY_SIZE);
    t3f.SetTweak(params);
    CBC_CTS_Mode_ExternalCipher::Decryption dec(t3f, &hkdf_hash[T3F_KEY_SIZE]);

    StreamTransformationFilter stf(dec, new ArraySink(buf, buf.size()));
    stf.Put(&data[HASH_SIZE + SALT_SIZE], buf.size());
    stf.MessageEnd();

    Kalyna512::Decryption kln(
        &hkdf_hash[T3F_KEY_SIZE + T3F_IV_SIZE + TWEAK_SIZE + HASH_KEY_SIZE],
        KLN_KEY_SIZE);
    CBC_CTS_Mode_ExternalCipher::Decryption kln_dec(
        kln, &hkdf_hash[T3F_KEY_SIZE + T3F_IV_SIZE + TWEAK_SIZE +
                        HASH_KEY_SIZE + KLN_KEY_SIZE]);

    StreamTransformationFilter kln_stf(kln_dec, new ArraySink(pad, pad.size()));
    kln_stf.Put(&data[HASH_SIZE + SALT_SIZE + buf.size()], pad.size());
    kln_stf.MessageEnd();

    xorbuf(buf, pad, pad.size());

    return buf;
}

void decrypt_file(char *keyf, char *inf, char *outf) {
    SecByteBlock key = read_key(keyf);
    SecByteBlock file = read_file(inf);

    SecByteBlock buf = decrypt(file, key);
    FileSink fsnk(outf);
    fsnk.Put(buf, buf.size());
}

void show_json(char *keyf, char *inf) {
    SecByteBlock key = read_key(keyf);
    SecByteBlock file = read_file(inf);

    SecByteBlock buf = decrypt(file, key);

    json j = json::parse(
        std::string(reinterpret_cast<const char *>(buf.data()), buf.size()));
    std::cout << inf << std::endl;
    std::cout << j.dump(4) << std::endl;
}

void show_totp(char *keyf, char *inf) {
    SecByteBlock key = read_key(keyf);
    SecByteBlock file = read_file(inf);
    SecByteBlock buf = decrypt(file, key);

    json j = json::parse(
        std::string(reinterpret_cast<const char *>(buf.data()), buf.size()));
    int digits = j["totp"]["digits"].get<int>();
    int period = j["totp"]["period"].get<int>();
    int algo = j["totp"]["algo"].get<int>();
    std::string secret = j["totp"]["secret"].get<std::string>();
    SecByteBlock sec_sbb(reinterpret_cast<const byte *>(secret.data()),
                         secret.size());

    SecByteBlock totp = get_totp(sec_sbb, digits, period, algo);
    std::cout << inf << std::endl;
    std::cout << (char *)totp.data() << std::endl;
}

void show_login(char *keyf, char *inf) {
    SecByteBlock key = read_key(keyf);
    SecByteBlock file = read_file(inf);
    SecByteBlock buf = decrypt(file, key);

    json j = json::parse(
        std::string(reinterpret_cast<const char *>(buf.data()), buf.size()));
    std::string username = j["username"].get<std::string>();
    std::string password = j["password"].get<std::string>();
    
    std::cout << inf << std::endl;
    std::cout << std::setw(10) << std::left << "username:";
    std::cout << username << std::endl;
    std::cout << std::setw(10) << std::left << "password:";
    std::cout << password << std::endl;
}

void merge(char *p, char *t) {
    std::ifstream f_p(p);
    json j_p = json::parse(f_p);
    std::ifstream f_t(t);
    json j_t = json::parse(f_t);
    j_p["totp"] = j_t;
    std::cout << j_p.dump(4) << std::endl;
}

std::string utc_time() {
    std::time_t time = std::time({});
    char timeString[std::size("yyyy-mm-dd hh:mm:ss UTC")];
    std::strftime(std::data(timeString), std::size(timeString), "%F %T UTC",
                  std::gmtime(&time));
    return timeString;
}

void gen_login(char *un, char *file, bool totp) {
    SecByteBlock pass(PASS_LEN);
    OS_GenerateRandomBlock(false, pass, pass.size());

    std::string encoded;
    StringSource ss(pass, pass.size(), true,
                    new Base64URLEncoder(new StringSink(encoded), false));
    json j;
    j["username"] = un;
    j["password"] = encoded;
    j["created"] = utc_time();
    j["note"] = "";

    if (totp) {
        j["totp"]["secret"] = "";
        j["totp"]["algo"] = 1;
        j["totp"]["period"] = 30;
        j["totp"]["digits"] = 6;
    }

    std::string data = j.dump(4);
    if (data.size() < T3F_BLOCK_SIZE + 2) {
        SecByteBlock tmp(T3F_BLOCK_SIZE + 2 - data.size());
        OS_GenerateRandomBlock(false, tmp, tmp.size());
        std::string pad;
        StringSource sss(tmp, tmp.size(), true,
                         new Base64URLEncoder(new StringSink(pad), false));
        j["pad"] = pad;
    }

    std::ofstream o(file);
    o << j.dump(4) << std::endl;
}

int main(int argc, char *argv[]) {
    try {
        if (argc == 8 && strcmp(argv[1], "-e") == 0 &&
            strcmp(argv[2], "-k") == 0 && strcmp(argv[4], "-i") == 0 &&
            strcmp(argv[6], "-o") == 0) {
            // passpp -e -k key -i input -o output
            encrypt_file(argv[3], argv[5], argv[7]);

        } else if (argc == 8 && strcmp(argv[1], "-d") == 0 &&
                   strcmp(argv[2], "-k") == 0 && strcmp(argv[4], "-i") == 0 &&
                   strcmp(argv[6], "-o") == 0) {
            // passpp -d -k key -i input -o output
            decrypt_file(argv[3], argv[5], argv[7]);

        } else if (argc == 6 && strcmp(argv[1], "-show-json") == 0 &&
                   strcmp(argv[2], "-k") == 0 && strcmp(argv[4], "-i") == 0) {
            // passpp -show-json -k key -i input
            show_json(argv[3], argv[5]);

        } else if (argc == 6 && strcmp(argv[1], "-show-totp") == 0 &&
                   strcmp(argv[2], "-k") == 0 && strcmp(argv[4], "-i") == 0) {
            // passpp -show-totp -k key -i input
            show_totp(argv[3], argv[5]);

        } else if (argc == 6 && strcmp(argv[1], "-show-login") == 0 &&
                   strcmp(argv[2], "-k") == 0 && strcmp(argv[4], "-i") == 0) {
            // passpp -show-totp -k key -i input
            show_login(argv[3], argv[5]);

        } else if (argc == 6 && strcmp(argv[1], "-merge") == 0 &&
                   strcmp(argv[2], "-p") == 0 && strcmp(argv[4], "-t") == 0) {
            // passpp -merge -p p -t t
            merge(argv[3], argv[5]);

        } else if (argc == 6 && strcmp(argv[1], "-gen-login") == 0 &&
                   strcmp(argv[2], "-u") == 0 && strcmp(argv[4], "-o") == 0) {
            // passpp -gen-login -u abc@def.com -o def.json
            gen_login(argv[3], argv[5], false);

        } else if (argc == 7 && strcmp(argv[1], "-gen-login") == 0 &&
                   strcmp(argv[2], "-with-totp") == 0 &&
                   strcmp(argv[3], "-u") == 0 && strcmp(argv[5], "-o") == 0) {
            // passpp -gen-login -with-totp -u abc@def.com -o def.json
            gen_login(argv[4], argv[6], true);

        } else {
            error_exit("[main] Wrong argv");
        }

    } catch (const Exception &ex) {
        std::cerr << ex.what() << std::endl;
        return -1;
    }
}