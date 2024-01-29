#include <algorithm>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>

#include <stdlib.h>
#include <termios.h>
#include <unistd.h>

#include <SQLiteCpp/SQLiteCpp.h>

#include <cryptopp/base32.h>
#include <cryptopp/base64.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/kalyna.h>
#include <cryptopp/misc.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/threefish.h>
using namespace CryptoPP;

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include <argon2.h>

// time
const uint32_t T_COST = 16;
// memory 1 << 16 ~ 64 mebibytes
const uint32_t M_COST = (1 << 18);
// parallelism
const uint32_t P_COST = 2;

const unsigned int PASS_LEN = 20;
const unsigned int KEY_SIZE = 1024;
const unsigned int TWEAK_SIZE = 16;
const unsigned int HASH_KEY_SIZE = 64;
const unsigned int HASH_SIZE = 64;
const unsigned int SALT_SIZE = 64;
const unsigned int T3F_IV_SIZE = 128;
const unsigned int T3F_KEY_SIZE = 128;
const unsigned int KLN_KEY_SIZE = 64;
const unsigned int KLN_IV_SIZE = 64;
const unsigned int T3F_BLOCK_SIZE = 128;
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

void init(char *dbf) {
    SQLite::Database db(dbf, SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE);

    // Begin transaction
    SQLite::Transaction transaction(db);

    db.exec(
        "CREATE TABLE user (uId INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, hash BLOB NOT NULL, value BLOB NOT NULL)");
    db.exec("CREATE UNIQUE INDEX idx_user ON user(name)");
    db.exec(
        "CREATE TABLE entry (eId INTEGER PRIMARY KEY, uId INTEGER NOT NULL, name TEXT NOT NULL, FOREIGN KEY(uId) REFERENCES user(uId))");
    db.exec("CREATE INDEX idx_entry ON entry(name)");
    db.exec(
        "CREATE TABLE data (dId INTEGER PRIMARY KEY, eId INTEGER NOT NULL, value BLOB NOT NULL, FOREIGN KEY(eId) REFERENCES entry(eId))");
    db.exec(
        "CREATE VIRTUAL TABLE search USING FTS5 (name, tokenize='porter unicode61', content='entry', content_rowid='eId')");

    // Commit transaction
    transaction.commit();
}

SecByteBlock encrypt(SecByteBlock data, SecByteBlock key) {
    SecByteBlock buf(HASH_SIZE + SALT_SIZE + data.size());
    OS_GenerateRandomBlock(false, &buf[HASH_SIZE], SALT_SIZE);

    SecByteBlock hkdf_hash(HKDF_SIZE);
    HKDF<SHA3_512> hkdf;
    hkdf.DeriveKey(hkdf_hash, hkdf_hash.size(), key, key.size(),
                   &buf[HASH_SIZE], SALT_SIZE, NULL, 0);

    Kalyna512::Encryption kln(
        &hkdf_hash[T3F_KEY_SIZE + T3F_IV_SIZE + TWEAK_SIZE + HASH_KEY_SIZE],
        KLN_KEY_SIZE);
    CBC_CTS_Mode_ExternalCipher::Encryption kln_enc(
        kln, &hkdf_hash[T3F_KEY_SIZE + T3F_IV_SIZE + TWEAK_SIZE +
                        HASH_KEY_SIZE + KLN_KEY_SIZE]);

    StreamTransformationFilter kln_stf(
        kln_enc, new ArraySink(&buf[HASH_SIZE + SALT_SIZE], data.size()));
    kln_stf.Put(data, data.size());
    kln_stf.MessageEnd();

    ConstByteArrayParameter twk(&hkdf_hash[T3F_KEY_SIZE + T3F_IV_SIZE],
                                TWEAK_SIZE, false);
    AlgorithmParameters params = MakeParameters(Name::Tweak(), twk);
    Threefish1024::Encryption t3f(&hkdf_hash[0], T3F_KEY_SIZE);
    t3f.SetTweak(params);
    CBC_CTS_Mode_ExternalCipher::Encryption enc(t3f, &hkdf_hash[T3F_KEY_SIZE]);

    StreamTransformationFilter stf(
        enc, new ArraySink(&buf[HASH_SIZE + SALT_SIZE], data.size()));
    stf.Put(&buf[HASH_SIZE + SALT_SIZE], data.size());
    stf.MessageEnd();

    SecByteBlock hmac_hash(HASH_SIZE);
    HMAC<SHA3_512> hmac;
    hmac.SetKey(&hkdf_hash[T3F_KEY_SIZE + T3F_IV_SIZE + TWEAK_SIZE],
                HASH_KEY_SIZE);
    hmac.Update(&buf[HASH_SIZE], SALT_SIZE + data.size());
    hmac.Final(hmac_hash);
    std::memcpy(&buf[0], hmac_hash, HASH_SIZE);

    return buf;
}

std::string ask_pass(std::string prompt) {
    termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    std::string pwd;
    std::cout << prompt;
    getline(std::cin, pwd);
    std::cout << std::endl;

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    return pwd;
}

std::string get_pass() {
    std::string p1 = ask_pass("Enter password: ");
    std::string p2 = ask_pass("Confirm password: ");
    if (p1 != p2) {
        CryptoPP::SecureWipeBuffer((byte *)p1.data(), p1.size());
        CryptoPP::SecureWipeBuffer((byte *)p2.data(), p2.size());
        error_exit("[get_pass] Unmatched passwords");
    }
    CryptoPP::SecureWipeBuffer((byte *)p2.data(), p2.size());

    return p1;
}

std::string hash_pwd(std::string pass) {
    size_t encodedlen = argon2_encodedlen(T_COST, M_COST, P_COST, SALT_SIZE,
                                          HASH_SIZE, Argon2_id);

    uint8_t *pwd = (uint8_t *)strdup(pass.data());
    uint32_t pwdlen = strlen((char *)pwd);
    SecByteBlock salt(SALT_SIZE);
    OS_GenerateRandomBlock(false, salt, salt.size());

    std::string hash(encodedlen, ' ');
    argon2id_hash_encoded(T_COST, M_COST, P_COST, pwd, pwdlen, salt,
                          salt.size(), HASH_SIZE, (char *)hash.data(),
                          encodedlen);

    CryptoPP::SecureWipeBuffer(pwd, pwdlen);
    return hash;
}

SecByteBlock hash_pwd(SecByteBlock salt, std::string pass) {
    uint8_t *pwd = (uint8_t *)strdup(pass.data());
    uint32_t pwdlen = strlen((char *)pwd);

    SecByteBlock hash(KEY_SIZE);
    argon2id_hash_raw(T_COST, M_COST, P_COST, pwd, pwdlen, salt, salt.size(),
                      hash, hash.size());

    CryptoPP::SecureWipeBuffer(pwd, pwdlen);
    return hash;
}

void add_user(char *dbf, char *name) {
    SecByteBlock key(KEY_SIZE);
    OS_GenerateRandomBlock(false, key, key.size());
    SecByteBlock salt(SALT_SIZE);
    OS_GenerateRandomBlock(false, salt, salt.size());

    std::string pass = get_pass();
    std::string hash_encoded = hash_pwd(pass);
    SecByteBlock hash = hash_pwd(salt, pass);
    SecByteBlock enc_key = encrypt(key, hash);
    CryptoPP::SecureWipeBuffer((byte *)pass.data(), pass.size());

    SecByteBlock salt_enc_key(salt.size() + enc_key.size());
    std::memcpy(&salt_enc_key[0], &salt[0], salt.size());
    std::memcpy(&salt_enc_key[SALT_SIZE], &enc_key[0], enc_key.size());

    std::string encoded;
    StringSource ss(salt_enc_key, salt_enc_key.size(), true,
                    new Base64URLEncoder(new StringSink(encoded), false));

    SQLite::Database db(dbf, SQLite::OPEN_READWRITE);

    // Begin transaction
    SQLite::Transaction transaction(db);

    SQLite::Statement q{
        db, "INSERT INTO user (name, hash, value) VALUES (?, ?, ?)"};
    q.bind(1, name);
    q.bind(2, hash_encoded);
    q.bind(3, encoded);
    q.exec();

    // Commit transaction
    transaction.commit();
}

SecByteBlock decode(std::string encoded) {
    std::string decoded;
    StringSource dec(encoded, true,
                     new Base64URLDecoder(new StringSink(decoded)));
    SecByteBlock sec_decoded(decoded.size());
    StringSource sec_dec(
        encoded, true,
        new Base64URLDecoder(new ArraySink(sec_decoded, sec_decoded.size())));
    return sec_decoded;
}

SecByteBlock decrypt(SecByteBlock data, SecByteBlock key) {
    SecByteBlock buf(data.size() - HASH_SIZE - SALT_SIZE);

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

    StreamTransformationFilter kln_stf(kln_dec, new ArraySink(buf, buf.size()));
    kln_stf.Put(buf, buf.size());
    kln_stf.MessageEnd();

    return buf;
}

void login(char *dbf, char *name) {
    SQLite::Database db(dbf, SQLite::OPEN_READWRITE);

    // Begin transaction
    SQLite::Transaction transaction(db);

    SQLite::Statement q{db, "SELECT value, hash FROM user WHERE name = ?"};
    q.bind(1, name);
    if (q.executeStep()) {
        std::string encoded = q.getColumn(0);
        SecByteBlock sec_decoded = decode(encoded);
        SecByteBlock salt(SALT_SIZE);
        std::memcpy(&salt[0], &sec_decoded[0], salt.size());
        SecByteBlock enc_key(sec_decoded.size() - SALT_SIZE);
        std::memcpy(&enc_key[0], &sec_decoded[SALT_SIZE], enc_key.size());

        std::string hash_encoded = q.getColumn(1);
        std::string pass = get_pass();
        if (argon2id_verify(hash_encoded.data(), pass.data(), pass.size()) !=
            ARGON2_OK) {
            error_exit("[login] Wrong password");
        }

        SecByteBlock hash = hash_pwd(salt, pass);
        CryptoPP::SecureWipeBuffer((byte *)pass.data(), pass.size());

        SecByteBlock key = decrypt(enc_key, hash);
        std::ofstream o(std::string(name) + ".key", std::ios::binary);
        o.write((const char *)key.data(), key.size());
    } else {
        error_exit("[login] Unknown name");
    }

    // Commit transaction
    transaction.commit();
}

void add(char *dbf, char *name, char *entry) {
    SQLite::Database db(dbf, SQLite::OPEN_READWRITE);
    db.exec("PRAGMA foreign_keys = ON");

    // Begin transaction
    SQLite::Transaction transaction(db);

    SQLite::Statement q_user{db, "SELECT uId FROM user WHERE name = ?"};
    q_user.bind(1, name);
    if (q_user.executeStep()) {
        uint32_t uId = q_user.getColumn(0);

        SQLite::Statement q_data{db,
                                 "INSERT INTO entry (uId, name) VALUES (?, ?)"};
        q_data.bind(1, uId);
        q_data.bind(2, entry);
        q_data.exec();
    } else {
        error_exit("[add] Unknown name");
    }

    // Commit transaction
    transaction.commit();
}

void show(char *dbf, char *user_name, char *entry_name) {
    SQLite::Database db(dbf, SQLite::OPEN_READWRITE);

    // Begin transaction
    SQLite::Transaction transaction(db);

    SQLite::Statement q_comb{
        db,
        "SELECT eId FROM entry WHERE uId = (SELECT uId FROM user WHERE name = ?) and name = ?"};
    q_comb.bind(1, user_name);
    q_comb.bind(2, entry_name);
    uint32_t eId;
    if (q_comb.executeStep()) {
        std::cout << user_name << "  " << entry_name << "  ";
        eId = q_comb.getColumn(0);
        std::cout << eId << " ";
    } else {
        error_exit("[show] Cannot find entry");
    }
    while (q_comb.executeStep()) {
        eId = q_comb.getColumn(0);
        std::cout << eId << " ";
    }
    std::cout << std::endl;

    // Commit transaction
    transaction.commit();
}

void add(char *dbf, char *keyf, char *eId, char *inputf) {
    std::ifstream f(inputf);
    json j = json::parse(f);
    std::string data = j.dump(4);
    if (data.size() < T3F_BLOCK_SIZE) {
        error_exit("[add] Smaller than T3F_BLOCK_SIZE");
    }
    SecByteBlock sbb(reinterpret_cast<const byte *>(data.data()), data.size());
    SecByteBlock key = read_key(keyf);
    SecByteBlock buf = encrypt(sbb, key);
    data.clear();

    std::string encoded;
    StringSource ss(buf, buf.size(), true,
                    new Base64URLEncoder(new StringSink(encoded), false));

    SQLite::Database db(dbf, SQLite::OPEN_READWRITE);
    db.exec("PRAGMA foreign_keys = ON");

    // Begin transaction
    SQLite::Transaction transaction(db);

    SQLite::Statement q{db, "INSERT INTO data (eId, value) VALUES (?, ?)"};
    q.bind(1, eId);
    q.bind(2, encoded);
    q.exec();

    // Commit transaction
    transaction.commit();
}

void show_json(char *dbf, char *keyf, char *eId) {
    SQLite::Database db(dbf, SQLite::OPEN_READWRITE);
    db.exec("PRAGMA foreign_keys = ON");

    // Begin transaction
    SQLite::Transaction transaction(db);

    SQLite::Statement q{
        db, "SELECT value FROM data WHERE eId = ? ORDER BY dId DESC LIMIT 1"};
    q.bind(1, eId);
    if (q.executeStep()) {
        std::string encoded = q.getColumn(0);
        SecByteBlock sec_decoded = decode(encoded);
        SecByteBlock key = read_key(keyf);
        SecByteBlock buf = decrypt(sec_decoded, key);

        std::string j =
            std::string(reinterpret_cast<const char *>(buf.data()), buf.size());
        std::cout << j << std::endl;
    } else {
        error_exit("[show_pwd] Cannot find entry");
    }
}

std::string utc_time() {
    std::time_t time = std::time({});
    char timeString[std::size("yyyy-mm-dd hh:mm:ss UTC")];
    std::strftime(std::data(timeString), std::size(timeString), "%F %T UTC",
                  std::gmtime(&time));
    return timeString;
}

void gen_login(char *un, char *file) {
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

void gen_totp(char *file) {
    json j;
    j["secret"] = "";
    j["created"] = utc_time();
    j["algo"] = 1;
    j["period"] = 30;
    j["digits"] = 6;

    std::string data = j.dump(4);
    if (data.size() < T3F_BLOCK_SIZE) {
        SecByteBlock tmp(T3F_BLOCK_SIZE - data.size());
        OS_GenerateRandomBlock(false, tmp, tmp.size());
        std::string pad;
        StringSource sss(tmp, tmp.size(), true,
                         new Base64URLEncoder(new StringSink(pad), false));
        j["pad"] = pad;
    }

    std::ofstream o(file);
    o << j.dump(4) << std::endl;
}

void rebuild_search(char *dbf) {
    SQLite::Database db(dbf, SQLite::OPEN_READWRITE);
    // Begin transaction
    SQLite::Transaction transaction(db);

    db.exec("DROP TABLE IF EXISTS search");
    db.exec(
        "CREATE VIRTUAL TABLE search USING FTS5 (eId, name, tokenize='porter unicode61', content='entry', content_rowid='eId')");
    db.exec("INSERT INTO search (eId, name) SELECT eId, name FROM entry");

    // Commit transaction
    transaction.commit();
}

void search(char *dbf, char *term) {
    SQLite::Database db(dbf, SQLite::OPEN_READWRITE);

    // Begin transaction
    SQLite::Transaction transaction(db);
    SQLite::Statement q{
        db,
        "SELECT eId, uId, name FROM entry WHERE eId IN (SELECT eId FROM search WHERE name MATCH ?) ORDER BY uId ASC, eId ASC"};
    q.bind(1, term);
    int count = 0;
    while (q.executeStep()) {
        count++;
        uint32_t eId = (uint32_t)q.getColumn(0);
        uint32_t uId = (uint32_t)q.getColumn(1);
        std::string entry_name = q.getColumn(2);

        SQLite::Statement q_user{db, "SELECT name FROM user WHERE uId = ?"};
        q_user.bind(1, uId);
        std::cout << std::setw(5) << std::left << eId;
        if (q_user.executeStep()) {
            std::string user_name = q_user.getColumn(0);
            std::cout << std::setw(10) << std::left << user_name;
            std::cout << std::setw(50) << std::left << entry_name;
        }

        SQLite::Statement q_data{db, "SELECT dId FROM data WHERE eId = ?"};
        q_data.bind(1, eId);
        std::vector<uint32_t> dId;
        while (q_data.executeStep()) {
            dId.push_back((uint32_t)q_data.getColumn(0));
        }
        for (auto i : dId) {
            std::cout << i << " ";
        }
        std::cout << std::endl;
    }
    if (count == 0) {
        std::cout << "[search] Not found" << std::endl;
    }

    // Commit transaction
    transaction.commit();
}

void show_totp(char *dbf, char *keyf, char *eId) {
    SQLite::Database db(dbf, SQLite::OPEN_READWRITE);
    db.exec("PRAGMA foreign_keys = ON");

    // Begin transaction
    SQLite::Transaction transaction(db);

    SQLite::Statement q{
        db, "SELECT value FROM data WHERE eId = ? ORDER BY dId DESC LIMIT 1"};
    q.bind(1, eId);
    if (q.executeStep()) {
        std::string encoded = q.getColumn(0);
        SecByteBlock sec_decoded = decode(encoded);
        SecByteBlock key = read_key(keyf);
        SecByteBlock buf = decrypt(sec_decoded, key);

        std::string j =
            std::string(reinterpret_cast<const char *>(buf.data()), buf.size());
        json js = json::parse(j);

        int digits = js["digits"].get<int>();
        int period = js["period"].get<int>();
        int algo = js["algo"].get<int>();
        std::string secret = js["secret"].get<std::string>();
        SecByteBlock sec_sbb(reinterpret_cast<const byte *>(secret.data()),
                             secret.size());

        SecByteBlock totp = get_totp(sec_sbb, digits, period, algo);

        SQLite::Statement q_entry{db, "SELECT name FROM entry WHERE eId = ?"};
        q_entry.bind(1, eId);
        if (q_entry.executeStep()) {
            std::string entry_name = q_entry.getColumn(0);
            std::cout << entry_name << "  ";
        }
        std::cout << (char *)totp.data() << std::endl;
        CryptoPP::SecureWipeBuffer(j.data(), j.size());
        CryptoPP::SecureWipeBuffer(secret.data(), secret.size());
    } else {
        error_exit("[show_otp] Cannot find entry");
    }

    // Commit transaction
    transaction.commit();
}

void del_max(char *dbf, char *eId) {
    SQLite::Database db(dbf, SQLite::OPEN_READWRITE);
    db.exec("PRAGMA foreign_keys = ON");

    // Begin transaction
    SQLite::Transaction transaction(db);

    SQLite::Statement q{
        db, "DELETE FROM data WHERE eId = ? and dId < (SELECT MAX(dId) FROM data WHERE eId = ?)"};
    q.bind(1, eId);
    int nr = q.exec();

    // Commit transaction
    transaction.commit();

    std::cout << "Change " << nr << " row(s)" << std::endl;
}

void del_eid_did(char *dbf, char *eId, char *dId) {
    SQLite::Database db(dbf, SQLite::OPEN_READWRITE);
    db.exec("PRAGMA foreign_keys = ON");

    // Begin transaction
    SQLite::Transaction transaction(db);

    SQLite::Statement q{
        db, "DELETE FROM data WHERE eId = ? and dId = ?"};
    q.bind(1, eId);
    q.bind(2, dId);
    int nr = q.exec();

    // Commit transaction
    transaction.commit();

    std::cout << "Change " << nr << " row(s)" << std::endl;
}

void test_totp(char *sec) {
    SecByteBlock sec_sbb(reinterpret_cast<const byte *>(sec), strlen(sec));
    int digits = 6;
    int period = 30;
    int algo = 1;
    SecByteBlock totp = get_totp(sec_sbb, digits, period, algo);
    std::cout << (char *)totp.data() << std::endl;
}

int main(int argc, char *argv[]) {
    try {
        if (argc == 3 && strcmp(argv[1], "init") == 0) {
            // passpp init abc.db
            init(argv[2]);

        } else if (argc == 6 && strcmp(argv[1], "add-user") == 0 &&
                   strcmp(argv[2], "-db") == 0 && strcmp(argv[4], "-n") == 0) {
            // passpp add-user -db abc.db -n name
            add_user(argv[3], argv[5]);

        } else if (argc == 6 && strcmp(argv[1], "login") == 0 &&
                   strcmp(argv[2], "-db") == 0 && strcmp(argv[4], "-n") == 0) {
            // passpp login -db abc.db -n name
            login(argv[3], argv[5]);

        } else if (argc == 8 && strcmp(argv[1], "add") == 0 &&
                   strcmp(argv[2], "-db") == 0 && strcmp(argv[4], "-n") == 0 &&
                   strcmp(argv[6], "-e") == 0) {
            // passpp add -db abc.db -n name -e abc.com
            add(argv[3], argv[5], argv[7]);

        } else if (argc == 8 && strcmp(argv[1], "show") == 0 &&
                   strcmp(argv[2], "-db") == 0 && strcmp(argv[4], "-n") == 0 &&
                   strcmp(argv[6], "-e") == 0) {
            // passpp show -db abc.db -n name -e abc.com
            show(argv[3], argv[5], argv[7]);

        } else if (argc == 10 && strcmp(argv[1], "add") == 0 &&
                   strcmp(argv[2], "-db") == 0 && strcmp(argv[4], "-k") == 0 &&
                   strcmp(argv[6], "-eId") == 0 && strcmp(argv[8], "-i") == 0) {
            // passpp add -db abc.db -k abc.key -eId eId -i abc.json
            add(argv[3], argv[5], argv[7], argv[9]);

        } else if (argc == 8 && strcmp(argv[1], "show-json") == 0 &&
                   strcmp(argv[2], "-db") == 0 && strcmp(argv[4], "-k") == 0 &&
                   strcmp(argv[6], "-eId") == 0) {
            // passpp show-json -db abc.db -k abc.key -eId eId
            show_json(argv[3], argv[5], argv[7]);

        } else if (argc == 6 && strcmp(argv[1], "gen-login") == 0 &&
                   strcmp(argv[2], "-u") == 0 && strcmp(argv[4], "-o") == 0) {
            // passpp gen-login -u abc@def.com -o def.json
            gen_login(argv[3], argv[5]);

        } else if (argc == 4 && strcmp(argv[1], "gen-totp") == 0 &&
                   strcmp(argv[2], "-o") == 0) {
            // passpp gen-totp -o def.json
            gen_totp(argv[3]);

        } else if (argc == 4 && strcmp(argv[1], "rebuild-search") == 0 &&
                   strcmp(argv[2], "-db") == 0) {
            // passpp rebuild-search -db abc.db
            rebuild_search(argv[3]);

        } else if (argc == 6 && strcmp(argv[1], "search") == 0 &&
                   strcmp(argv[2], "-db") == 0 && strcmp(argv[4], "-t") == 0) {
            // passpp search -db abc.db -t abc
            search(argv[3], argv[5]);

        } else if (argc == 8 && strcmp(argv[1], "show-totp") == 0 &&
                   strcmp(argv[2], "-db") == 0 && strcmp(argv[4], "-k") == 0 &&
                   strcmp(argv[6], "-eId") == 0) {
            // passpp show-totp -db abc.db -k abc.key -eId eId
            show_totp(argv[3], argv[5], argv[7]);

        } else if (argc == 6 && strcmp(argv[1], "del") == 0 &&
                   strcmp(argv[2], "-db") == 0 && strcmp(argv[4], "-eId") == 0) {
            // passpp del -db abc.db -eId eId
            del_max(argv[3], argv[5]);

        } else if (argc == 8 && strcmp(argv[1], "del") == 0 &&
                   strcmp(argv[2], "-db") == 0 && strcmp(argv[4], "-eId") == 0 && strcmp(argv[6], "-dId") == 0) {
            // passpp del -db abc.db -eId eId -dId dId
            del_eid_did(argv[3], argv[5], argv[7]);

        } else if (argc == 4 && strcmp(argv[1], "test-totp") == 0 &&
                   strcmp(argv[2], "-s") == 0) {
            // passpp test-totp -s sec
            test_totp(argv[3]);

        } else {
            error_exit("[main] Wrong argv");
        }
    } catch (const Exception &ex) {
        std::cerr << ex.what() << std::endl;
        return -1;
    }

    return 0;
}
