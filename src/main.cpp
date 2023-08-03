#include <fstream>
#include <iostream>

#include <SQLiteCpp/SQLiteCpp.h>

#include <cryptopp/base64.h>
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

const unsigned int PASS_LEN = 20;
const unsigned int KEY_FILE_SIZE = 1024;
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
        if (get_file_size(&infile) != KEY_FILE_SIZE) {
            error_exit("[read_key] Wrong key file");
        }
        SecByteBlock key(KEY_FILE_SIZE);
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
            "CREATE TABLE login (lId INTEGER PRIMARY KEY, value BLOB NOT NULL)");
        db.exec(
            "CREATE TABLE entry (eId INTEGER PRIMARY KEY, lId INTEGER NOT NULL, value TEXT NOT NULL, FOREIGN KEY(lId) REFERENCES login(lId))");
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

void add(char *dbf, char *value) {
    try {
        SQLite::Database db(dbf, SQLite::OPEN_READWRITE);

        // Begin transaction
        SQLite::Transaction transaction(db);

        SQLite::Statement q_data{db, "INSERT INTO entry (value) VALUES (?)"};
        q_data.bind(1, value);
        q_data.exec();

        SQLite::Statement q_last{db, "SELECT last_insert_rowid()"};
        while (q_last.executeStep()) {
            uint32_t eId = (uint32_t)q_last.getColumn(0);
            std::cout << "eId: " << eId << std::endl;
        }

        SQLite::Statement q_search{db, "INSERT INTO search (value) VALUES (?)"};
        q_search.bind(1, value);
        q_search.exec();

        // Commit transaction
        transaction.commit();
    } catch (const Exception &ex) {
        std::cerr << ex.what() << std::endl;
        exit(-1);
    }
}

SecByteBlock encrypt(SecByteBlock data, char *keyf) {
    try {
        SecByteBlock key = read_key(keyf);
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

SecByteBlock decrypt(SecByteBlock data, char *keyf) {
    try {
        SecByteBlock key = read_key(keyf);
        SecByteBlock buf(data.size() - HASH_SIZE - SALT_SIZE);

        SecByteBlock hkdf_hash(HKDF_SIZE);
        HKDF<SHA3_512> hkdf;
        hkdf.DeriveKey(hkdf_hash, hkdf_hash.size(), key, key.size(),
                       &data[HASH_SIZE], SALT_SIZE, NULL, 0);

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

        SecByteBlock hmac_hash(HASH_SIZE);
        HMAC<SHA3_512> hmac;
        hmac.SetKey(&hkdf_hash[ENC_KEY_SIZE + IV_SIZE + TWEAK_SIZE],
                    HASH_KEY_SIZE);
        hmac.Update(&data[HASH_SIZE], data.size() - HASH_SIZE);
        hmac.Final(hmac_hash);
        SecByteBlock hash(HASH_SIZE);
        std::memcpy(hash, &data[0], HASH_SIZE);
        if (hash != hmac_hash) {
            error_exit("[main] Wrong HMAC");
        }
        CryptoPP::SecureWipeBuffer(key.data(), key.size());
        CryptoPP::SecureWipeBuffer(hkdf_hash.data(), hkdf_hash.size());

        return buf;
    } catch (const Exception &ex) {
        std::cerr << ex.what() << std::endl;
        exit(-1);
    }
}

void add(char *dbf, char *keyf, char *eId, char *file) {
    std::ifstream f(file);
    json j = json::parse(f);
    std::string data = j.dump(4);
    if (data.size() < BLOCK_SIZE) {
        error_exit("[add] Smaller than BLOCK_SIZE");
    }
    SecByteBlock sbb(reinterpret_cast<const byte *>(data.data()), data.size());
    SecByteBlock buf = encrypt(sbb, keyf);
    data.clear();

    std::string encoded;
    StringSource ss(buf, buf.size(), true,
                    new Base64URLEncoder(new StringSink(encoded), false));

    try {
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
    } catch (const Exception &ex) {
        std::cerr << ex.what() << std::endl;
        exit(-1);
    }
}

void show(char *dbf, char *keyf, char *eId) {
    try {
        SQLite::Database db(dbf, SQLite::OPEN_READWRITE);
        db.exec("PRAGMA foreign_keys = ON");

        // Begin transaction
        SQLite::Transaction transaction(db);

        SQLite::Statement q{
            db,
            "SELECT value FROM data WHERE eId = ? ORDER BY dId DESC LIMIT 1"};
        q.bind(1, eId);
        while (q.executeStep()) {
            std::string encoded = q.getColumn(0);
            std::string decoded;
            StringSource dec(encoded, true,
                             new Base64URLDecoder(new StringSink(decoded)));
            SecByteBlock sec_decoded(decoded.size());
            StringSource sec_dec(encoded, true,
                                 new Base64URLDecoder(new ArraySink(
                                     sec_decoded, sec_decoded.size())));
            SecByteBlock buf = decrypt(sec_decoded, keyf);
            std::string j = std::string(
                reinterpret_cast<const char *>(buf.data()), buf.size());
            json js = json::parse(j);
            std::cout << "username: " + js["username"].get<std::string>()
                      << std::endl;
            std::cout << "password: " + js["password"].get<std::string>()
                      << std::endl;
            std::cout << "note: " + js["note"].get<std::string>() << std::endl;
        }

        // Commit transaction
        transaction.commit();
    } catch (const Exception &ex) {
        std::cerr << ex.what() << std::endl;
        exit(-1);
    }
}

void generate(char *un, char *file) {
    try {
        SecByteBlock pass(PASS_LEN);
        OS_GenerateRandomBlock(false, pass, pass.size());

        std::string encoded;
        StringSource ss(pass, pass.size(), true,
                        new Base64URLEncoder(new StringSink(encoded), false));
        json j;
        j["username"] = un;
        j["password"] = encoded;
        j["note"] = "";
        j["pad"] = "";

        std::string data = j.dump(4);
        if (data.size() < BLOCK_SIZE + 2) {
            SecByteBlock tmp(BLOCK_SIZE + 2 - data.size());
            OS_GenerateRandomBlock(false, tmp, tmp.size());
            std::string pad;
            StringSource sss(tmp, tmp.size(), true,
                             new Base64URLEncoder(new StringSink(pad), false));
            j["pad"] = pad;
        }

        std::ofstream o(file);
        o << j.dump(4) << std::endl;
    } catch (const Exception &ex) {
        std::cerr << ex.what() << std::endl;
        exit(-1);
    }
}

void add_gen(char *dbf, char *un, char *file, char *value) {
    add(dbf, value);
    generate(un, file);
}

void search(char *dbf, char *term) {
    try {
        SQLite::Database db(dbf, SQLite::OPEN_READWRITE);
        db.exec("PRAGMA foreign_keys = ON");

        // Begin transaction
        SQLite::Transaction transaction(db);
        SQLite::Statement q{
            db,
            "select * from entry where eId in (select rowid from search where value match ?)"};
        q.bind(1, term);
        while (q.executeStep()) {
            uint32_t dId = (uint32_t)q.getColumn(0);
            std::string value = q.getColumn(1);
            SQLite::Statement q_his{db, "select dId from data where eId = ?"};
            q_his.bind(1, dId);
            std::vector<uint32_t> hId;
            while (q_his.executeStep()) {
                hId.push_back((uint32_t)q_his.getColumn(0));
            }

            std::cout << std::setw(5) << std::left << dId;
            std::cout << std::setw(25) << std::left << value;
            for (auto i : hId) {
                std::cout << i << " ";
            }
            std::cout << std::endl;
        }

        // Commit transaction
        transaction.commit();
    } catch (const Exception &ex) {
        std::cerr << ex.what() << std::endl;
        exit(-1);
    }
}

int main(int argc, char *argv[]) {
    if (argc == 3 && strcmp(argv[1], "init") == 0) {
        // passpp init abc.db
        init(argv[2]);
    } else if (argc == 5 && strcmp(argv[1], "add") == 0 &&
               strcmp(argv[2], "-db") == 0) {
        // passpp add -db abc.db test/abc.com
        add(argv[3], argv[4]);
    } else if (argc == 9 && strcmp(argv[1], "add") == 0 &&
               strcmp(argv[2], "-db") == 0 && strcmp(argv[4], "-k") == 0 &&
               strcmp(argv[6], "-eId") == 0) {
        // passpp add -db abc.db -k abc.key -eId 1 abc.json
        add(argv[3], argv[5], argv[7], argv[8]);
    } else if (argc == 9 && strcmp(argv[1], "add") == 0 &&
               strcmp(argv[2], "-db") == 0 && strcmp(argv[4], "-u") == 0 &&
               strcmp(argv[6], "-f") == 0) {
        // passpp add -db abc.db -u abc@def.com -f abc.json test/abc.com
        add_gen(argv[3], argv[5], argv[7], argv[8]);
    } else if (argc == 8 && strcmp(argv[1], "show") == 0 &&
               strcmp(argv[2], "-db") == 0 && strcmp(argv[4], "-k") == 0 &&
               strcmp(argv[6], "-eId") == 0) {
        // passpp show -db abc.db -k abc.key -eId 1
        show(argv[3], argv[5], argv[7]);
    } else if (argc == 5 && strcmp(argv[1], "search") == 0 &&
               strcmp(argv[2], "-db") == 0) {
        // passpp search -db abc.db abc
        search(argv[3], argv[4]);
    } else if (argc == 5 && strcmp(argv[1], "gen") == 0 &&
               strcmp(argv[2], "-u") == 0) {
        // passpp gen -u abc@def.com def.json
        generate(argv[3], argv[4]);
    } else {
        error_exit("[main] Wrong argv");
    }

    return 0;

    // cotp_error_t err;
    // const char *K = "JBSWY3DPEHPK3PXP";
    // char *totp = get_totp (K, 6, 30, SHA1, &err);
    // std::cout << totp << std::endl;
}
