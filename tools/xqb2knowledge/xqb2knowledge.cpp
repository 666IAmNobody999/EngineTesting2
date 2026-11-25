/*
  xqb2knowledge: 把 XQB 开局库（鲨鱼 / fisherfan xqbook 格式，SQLite）转换成
  幻神引擎读取的 EngineKnowledge.bin。

  用法：xqb2knowledge 输入.xqb [输出.bin]
        （Windows 可直接把 .xqb 文件拖到 exe 上；输出默认为输入文件同一文件夹
        内的 EngineKnowledge.bin）

  EngineKnowledge.bin 格式（小端序）：
    文件头 16 字节：  "HSEK"、u32 版本 (1)、u64 记录数
    每条记录 24 字节：u64 局面键、u16 着法、i16 分数、u32 胜、u32 和、u32 负
  局面键是 XQB key 字段（BLOB）的 FNV-1a 64 位哈希，着法保留 XQB 的编码
  ((起行 << 12) | (起列 << 8) | (终行 << 4) | 终列，以 key 的标准化局面为准)。
  记录按 (局面键, 着法) 排序，引擎直接在文件内二分查找，不需整个载入内存。
  valid = 0（停用）的着法不写入。
*/

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "sqlite3.h"

#ifdef _WIN32
    #include <windows.h>
#endif

namespace {

struct Rec {
    uint64_t key;
    uint16_t move;
    int16_t  score;
    uint32_t win, draw, lost;
};

uint64_t fnv1a(const unsigned char* p, int n) {
    uint64_t h = 0xCBF29CE484222325ULL;
    for (int i = 0; i < n; ++i)
        h = (h ^ p[i]) * 0x100000001B3ULL;
    return h;
}

void put(std::string& s, uint64_t v, int n) {
    for (int i = 0; i < n; ++i)
        s.push_back(char((v >> (8 * i)) & 0xFF));
}

uint32_t clamp_u32(sqlite3_int64 v) { return v < 0 ? 0 : v > 0xFFFFFFFFLL ? 0xFFFFFFFFU : uint32_t(v); }

FILE* open_file(const std::string& utf8, const char* mode) {
#ifdef _WIN32
    int          n = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &w[0], n);
    std::wstring m(mode, mode + std::strlen(mode));
    return _wfopen(w.c_str(), m.c_str());
#else
    return std::fopen(utf8.c_str(), mode);
#endif
}

bool rename_file(const std::string& from, const std::string& to) {
#ifdef _WIN32
    auto wide = [](const std::string& s) {
        int          n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
        std::wstring w(n, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
        return w;
    };
    return MoveFileExW(wide(from).c_str(), wide(to).c_str(), MOVEFILE_REPLACE_EXISTING) != 0;
#else
    return std::rename(from.c_str(), to.c_str()) == 0;
#endif
}

int run(const std::vector<std::string>& args) {
    if (args.size() < 2)
    {
        std::printf("用法：xqb2knowledge 输入.xqb [输出.bin]\n"
                    "（Windows 可直接把 .xqb 文件拖到本程序上）\n");
        return 1;
    }
    const std::string in = args[1];
    std::string       out;
    if (args.size() > 2)
        out = args[2];
    else
    {
        const size_t slash = in.find_last_of("/\\");
        out = (slash == std::string::npos ? std::string() : in.substr(0, slash + 1))
            + "EngineKnowledge.bin";
    }

    sqlite3* db = nullptr;
    if (sqlite3_open_v2(in.c_str(), &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK)
    {
        std::printf("无法打开 %s：%s\n", in.c_str(), db ? sqlite3_errmsg(db) : "");
        sqlite3_close(db);
        return 1;
    }
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, "SELECT key, move, score, win, draw, lost, valid FROM book", -1,
                           &st, nullptr)
        != SQLITE_OK)
    {
        std::printf("不是 XQB 开局库（找不到 book 表）：%s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    std::vector<Rec> recs;
    uint64_t         rows = 0, disabled = 0, bad = 0;
    int              rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW)
    {
        if (++rows % 1000000 == 0)
            std::printf("已读取 %llu 行…\n", (unsigned long long) rows), std::fflush(stdout);
        const auto* key = static_cast<const unsigned char*>(sqlite3_column_blob(st, 0));
        const int   len = sqlite3_column_bytes(st, 0);
        const int   mv  = sqlite3_column_int(st, 1);
        const int   fr = (mv >> 12) & 15, fc = (mv >> 8) & 15, tr = (mv >> 4) & 15, tc = mv & 15;
        if (!key || len <= 0 || mv < 0 || mv > 0xFFFF || fr > 9 || tr > 9 || fc > 8 || tc > 8)
        {
            ++bad;
            continue;
        }
        if (sqlite3_column_type(st, 6) != SQLITE_NULL && sqlite3_column_int64(st, 6) == 0)
        {
            ++disabled;
            continue;
        }
        Rec r;
        r.key   = fnv1a(key, len);
        r.move  = uint16_t(mv);
        r.score = int16_t(std::clamp<sqlite3_int64>(sqlite3_column_int64(st, 2), -32000, 32000));
        r.win   = clamp_u32(sqlite3_column_int64(st, 3));
        r.draw  = clamp_u32(sqlite3_column_int64(st, 4));
        r.lost  = clamp_u32(sqlite3_column_int64(st, 5));
        recs.push_back(r);
    }
    const bool ok = rc == SQLITE_DONE;
    if (!ok)
        std::printf("读取出错：%s\n", sqlite3_errmsg(db));
    sqlite3_finalize(st);
    sqlite3_close(db);
    if (!ok)
        return 1;

    // Same position and move more than once (e.g. merged books): keep the row with
    // the most games.
    std::sort(recs.begin(), recs.end(), [](const Rec& a, const Rec& b) {
        if (a.key != b.key)
            return a.key < b.key;
        if (a.move != b.move)
            return a.move < b.move;
        return uint64_t(a.win) + a.draw + a.lost > uint64_t(b.win) + b.draw + b.lost;
    });
    const size_t before = recs.size();
    recs.erase(std::unique(recs.begin(), recs.end(),
                           [](const Rec& a, const Rec& b) { return a.key == b.key && a.move == b.move; }),
               recs.end());

    const std::string tmp = out + ".tmp";
    FILE*             f   = open_file(tmp, "wb");
    if (!f)
    {
        std::printf("无法写入 %s\n", tmp.c_str());
        return 1;
    }
    std::string buf = "HSEK";
    put(buf, 1, 4);
    put(buf, recs.size(), 8);
    bool written = std::fwrite(buf.data(), 1, buf.size(), f) == buf.size();
    buf.clear();
    for (size_t i = 0; i < recs.size() && written; ++i)
    {
        const Rec& r = recs[i];
        put(buf, r.key, 8);
        put(buf, r.move, 2);
        put(buf, uint16_t(r.score), 2);
        put(buf, r.win, 4);
        put(buf, r.draw, 4);
        put(buf, r.lost, 4);
        if (buf.size() >= (1 << 20) || i + 1 == recs.size())
        {
            written = std::fwrite(buf.data(), 1, buf.size(), f) == buf.size();
            buf.clear();
        }
    }
    written = std::fclose(f) == 0 && written;
    if (!written || !rename_file(tmp, out))
    {
        std::printf("写入 %s 失败（磁盘已满？）\n", out.c_str());
        return 1;
    }

    size_t positions = 0;
    for (size_t i = 0; i < recs.size(); ++i)
        positions += i == 0 || recs[i].key != recs[i - 1].key;
    std::printf("完成：%s\n"
                "  读取 %llu 行，停用 (valid=0) %llu，无效 %llu，重复 %llu\n"
                "  写入 %llu 个着法，%llu 个局面，文件 %.1f MB\n",
                out.c_str(), (unsigned long long) rows, (unsigned long long) disabled,
                (unsigned long long) bad, (unsigned long long) (before - recs.size()),
                (unsigned long long) recs.size(), (unsigned long long) positions,
                (16.0 + 24.0 * recs.size()) / (1024 * 1024));
    return 0;
}

}  // namespace

#ifdef _WIN32
int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);
    std::vector<std::string> args;
    for (int i = 0; i < argc; ++i)
    {
        int         n = WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, nullptr, 0, nullptr, nullptr);
        std::string s(n > 0 ? n - 1 : 0, '\0');
        WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, &s[0], n, nullptr, nullptr);
        args.push_back(s);
    }
    const int r = run(args);
    // Started by drag and drop (own console window): keep the result visible.
    DWORD pids[2];
    if (GetConsoleProcessList(pids, 2) == 1)
    {
        std::printf("\n按回车键退出…");
        std::getchar();
    }
    return r;
}
#else
int main(int argc, char** argv) { return run(std::vector<std::string>(argv, argv + argc)); }
#endif
