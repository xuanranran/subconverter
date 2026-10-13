# 项目字体

仅随项目提供 **Twemoji Mozilla** 和 **Google Sans**。其余全局字体依照设备安装情况回退，不复制操作系统字体。

## 来源与许可

- [Twemoji Mozilla v0.7.0](https://github.com/mozilla/twemoji-colr/releases/tag/v0.7.0)：Mozilla Foundation 的 COLR/CPAL 彩色字体，使用 [Twemoji](https://github.com/twitter/twemoji) 表情图形。代码采用 Apache 2.0，图形采用 [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)。原始许可见 [TwemojiMozilla-LICENSE.md](licenses/TwemojiMozilla-LICENSE.md)。本版本包含 Twemoji 14 字符集，不保证支持更新的表情。
- [Google Sans](https://github.com/googlefonts/googlesans)：Google LLC 字体，采用 SIL Open Font License 1.1。普通与斜体均保留可变字重 400–700，以及原字体的 opsz 和 GRAD 轴。原始许可见 [GoogleSans-OFL.txt](licenses/GoogleSans-OFL.txt)，商标说明见 [GoogleSans-TRADEMARKS.md](licenses/GoogleSans-TRADEMARKS.md)。

本项目仅将上游 TTF 压缩为 WOFF2，保留字形、字体名称、布局及可变/彩色表，不裁剪字形，不修改视觉设计。[manifest.json](manifest.json) 记录固定版本来源、源文件与输出文件 SHA-256。

## 加载方式

`src/fonts.css` 注册字体，`src/style.css` 定义全局字体顺序。优先读取同名字体的本机安装版本，否则从当前站点的 `fonts/` 下载；使用 `font-display: swap`，不阻塞正文显示。Google Sans 位于指定字体栈末尾，只在前面字体不能满足时加载。

Twemoji 的 `unicode-range` 按实际字符映射生成，排除 ASCII 数字与标点，避免影响普通文本。彩色显示依赖浏览器支持 COLR/CPAL。两种字体没有覆盖的中文字符继续使用浏览器的系统回退字体。

## 更新

日常 `npm ci` / `npm run build` 直接使用已保存的字体，无需 Python 或外网下载。需要更新字体来源时，修改 `scripts/vendor-fonts.py` 中的固定版本，再运行：

```shell
python -m pip install fonttools brotli requests
python scripts/vendor-fonts.py
```

生成结果和原始许可一起提交。发布构建会复制 `public/fonts/`，适用于离线部署和子目录部署。
