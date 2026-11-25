# xqb2knowledge

把 XQB 开局库（鲨鱼 / fisherfan xqbook 格式）转换成幻神引擎读取的 `EngineKnowledge.bin`。

- 用法：`xqb2knowledge 输入.xqb [输出.bin]`，Windows 可直接把 `.xqb` 拖到 `xqb2knowledge.exe` 上。输出默认是输入文件同一文件夹内的 `EngineKnowledge.bin`。
- `valid = 0`（停用）的着法不写入；同一局面同一着法重复时保留局数最多的一行。
- 把 `EngineKnowledge.bin` 放在引擎 exe 同一文件夹（或在 `EngineKnowledge File` 选项填完整路径）。
- 编译：`sh build.sh`（Linux）或 `sh build.sh win`（MinGW-w64 生成 Windows exe）。

文件格式及引擎选招规则见 `src/engine.cpp` 的 `Knowledge` 部分。
