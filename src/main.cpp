#include <fstream>
#include <iostream>

#include <termios.h>
#include <unistd.h>

#include <SQLiteCpp/SQLiteCpp.h>

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

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include <cotp.h>

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
const unsigned int IV_SIZE = 128;
const unsigned int ENC_KEY_SIZE = 128;
const unsigned int BLOCK_SIZE = 128;
const unsigned int HKDF_SIZE =
    ENC_KEY_SIZE + IV_SIZE + TWEAK_SIZE + HASH_KEY_SIZE;

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
    try {
        std::ifstream infile(keyf, std::ios::in | std::ios::binary);
        if (get_file_size(&infile) != KEY_SIZE) {
            error_exit("[read_key] Wrong key file");
        }
        SecByteBlock key(KEY_SIZE);
        infile.read((char *)key.data(), key.size());
        infile.close();
        return key;
    } catch (const Exception &ex) {
        std::cerr << ex.what() << std::endl;
        exit(-1);
    }
}

void init(char *dbf) {
    try {
        SQLite::Database db(dbf, SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE);

        // Begin transaction
        SQLite::Transaction transaction(db);

        db.exec(
            "CREATE TABLE user (uId INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, hash BLOB NOT NULL, value BLOB NOT NULL)");
        db.exec("CREATE UNIQUE INDEX idx_user ON user(name)");
        db.exec(
            "CREATE TABLE entry (eId INTEGER PRIMARY KEY, uId INTEGER NOT NULL, name TEXT NOT NULL, FOREIGN KEY(uId) REFERENCES user(uId))");
        db.exec("CREATE UNIQUE INDEX idx_entry ON entry(value)");
        db.exec(
            "CREATE TABLE data (dId INTEGER PRIMARY KEY, eId INTEGER NOT NULL, value BLOB NOT NULL, FOREIGN KEY(eId) REFERENCES data(eId))");
        db.exec(
            "CREATE VIRTUAL TABLE search USING FTS5 (value, tokenize='porter unicode61', content='entry', content_rowid='eId')");

        // Commit transaction
        transaction.commit();
    } catch (const Exception &ex) {
        std::cerr << ex.what() << std::endl;
        exit(-1);
    }
}

SecByteBlock encrypt(SecByteBlock data, SecByteBlock key) {
    try {
        SecByteBlock buf(HASH_SIZE + SALT_SIZE + data.size());
        OS_GenerateRandomBlock(false, &buf[HASH_SIZE], SALT_SIZE);

        SecByteBlock hkdf_hash(HKDF_SIZE);
        HKDF<SHA3_512> hkdf;
        hkdf.DeriveKey(hkdf_hash, hkdf_hash.size(), key, key.size(),
                       &buf[HASH_SIZE], SALT_SIZE, NULL, 0);

        ConstByteArrayParameter twk(&hkdf_hash[ENC_KEY_SIZE + IV_SIZE],
                                    TWEAK_SIZE, false);
        AlgorithmParameters params = MakeParameters(Name::Tweak(), twk);
        Threefish1024::Encryption t3f(&hkdf_hash[0], ENC_KEY_SIZE);
        t3f.SetTweak(params);
        CBC_CTS_Mode_ExternalCipher::Encryption enc(t3f,
                                                    &hkdf_hash[ENC_KEY_SIZE]);
        StreamTransformationFilter stf(
            enc, new ArraySink(&buf[HASH_SIZE + SALT_SIZE], data.size()));
        stf.Put(data, data.size());
        stf.MessageEnd();

        SecByteBlock hmac_hash(HASH_SIZE);
        HMAC<SHA3_512> hmac;
        hmac.SetKey(&hkdf_hash[ENC_KEY_SIZE + IV_SIZE + TWEAK_SIZE],
                    HASH_KEY_SIZE);
        hmac.Update(&buf[HASH_SIZE], SALT_SIZE + data.size());
        hmac.Final(hmac_hash);
        std::memcpy(&buf[0], hmac_hash, HASH_SIZE);
        CryptoPP::SecureWipeBuffer(key.data(), key.size());
        CryptoPP::SecureWipeBuffer(hkdf_hash.data(), hkdf_hash.size());

        return buf;
    } catch (const Exception &ex) {
        std::cerr << ex.what() << std::endl;
        exit(-1);
    }
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
    try {
        SecByteBlock buf(data.size() - HASH_SIZE - SALT_SIZE);

        SecByteBlock hkdf_hash(HKDF_SIZE);
        HKDF<SHA3_512> hkdf;
        hkdf.DeriveKey(hkdf_hash, hkdf_hash.size(), key, key.size(),
                       &data[HASH_SIZE], SALT_SIZE, NULL, 0);

        SecByteBlock hmac_hash(HASH_SIZE);
        HMAC<SHA3_512> hmac;
        hmac.SetKey(&hkdf_hash[ENC_KEY_SIZE + IV_SIZE + TWEAK_SIZE],
                    HASH_KEY_SIZE);
        hmac.Update(&data[HASH_SIZE], data.size() - HASH_SIZE);
        hmac.Final(hmac_hash);
        SecByteBlock hash(HASH_SIZE);
        std::memcpy(hash, &data[0], HASH_SIZE);
        if (hash != hmac_hash) {
            error_exit("[decrypt] Wrong HMAC");
        }

        ConstByteArrayParameter twk(&hkdf_hash[ENC_KEY_SIZE + IV_SIZE],
                                    TWEAK_SIZE, false);
        AlgorithmParameters params = MakeParameters(Name::Tweak(), twk);
        Threefish1024::Decryption t3f(&hkdf_hash[0], ENC_KEY_SIZE);
        t3f.SetTweak(params);
        CBC_CTS_Mode_ExternalCipher::Decryption dec(t3f,
                                                    &hkdf_hash[ENC_KEY_SIZE]);
        StreamTransformationFilter stf(dec, new ArraySink(buf, buf.size()));
        stf.Put(&data[HASH_SIZE + SALT_SIZE], buf.size());
        stf.MessageEnd();

        return buf;
    } catch (const Exception &ex) {
        std::cerr << ex.what() << std::endl;
        exit(-1);
    }
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

        SQLite::Statement q_data{
            db, "INSERT INTO entry (uId, value) VALUES (?, ?)"};
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
        std::cout << user_name << "  " << entry_name;
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
    if (data.size() < BLOCK_SIZE) {
        error_exit("[add] Smaller than BLOCK_SIZE");
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

        } else {
            error_exit("[main] Wrong argv");
        }
    } catch (const Exception &ex) {
        std::cerr << ex.what() << std::endl;
        return -1;
    }

    return 0;
}
