// LittleFS 的最小替身，只为语法检查与主机侧运行测试。
//
// 运行测试（tests/host/test_keystore.cpp）由 shim_env.cpp 提供真实行为：
// 一个内存文件系统。这里只声明接口与载体，不实现任何语义。
#ifndef ROCKEY_STUB_LITTLEFS_H
#define ROCKEY_STUB_LITTLEFS_H

#include <stdint.h>
#include <stddef.h>
#include <string>
#include <vector>

// LittleFS::File 的最小替身，签名对齐 vault_fs.cpp 的用法。
class File {
 public:
  File() = default;
  operator bool() const;
  size_t write(const uint8_t* buf, size_t len);
  size_t read(uint8_t* buf, size_t len);
  size_t size() const;
  void close();
  bool rename(const char* path);

 private:
  friend class LittleFSClass;
  bool ok_ = false;
  char mode_ = 0;
  std::string path_;
  std::vector<uint8_t> data_;
  size_t pos_ = 0;
};

class LittleFSClass {
 public:
  bool begin(bool formatOnFail = false, const char* partition = nullptr, int maxOpenFiles = 10,
             const char* label = nullptr);
  bool exists(const char* path);
  bool mkdir(const char* path);
  bool remove(const char* path);
  bool rename(const char* from, const char* to);
  File open(const char* path, const char* mode = "r");
};

extern LittleFSClass LittleFS;

#endif  // ROCKEY_STUB_LITTLEFS_H
