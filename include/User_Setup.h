// TFT_eSPI 用户配置 —— M5Stack Core BASIC v2.7
//
// 该文件通过 -include 在每个翻译单元前置，配合 USER_SETUP_LOADED=1
// 跳过库自带 User_Setup.h。板级引脚定义与 docs/冻结/硬件清单.md 一致。

#ifndef ROCKEY_USER_SETUP_H
#define ROCKEY_USER_SETUP_H

#define ILI9341_DRIVER
#define M5STACK
#define TFT_WIDTH  240
#define TFT_HEIGHT 320

#define TFT_MISO 19
#define TFT_MOSI 23
#define TFT_SCLK 18
#define TFT_CS   14
#define TFT_DC   27
#define TFT_RST  33
#define TFT_BL   32

#define TFT_RGB_ORDER TFT_BGR

// TFT_eSPI 自带 ASCII 字库（Rockey 自有 CJK 字库在 i18n/fonts）
#define LOAD_GLCD
#define LOAD_FONT2
#define LOAD_FONT4
#define LOAD_FONT6
#define LOAD_FONT7
#define LOAD_FONT8

#define SMOOTH_FONT

#define SUPPORT_TRANSACTIONS
#define TFT_DRAWBITMAP
#define TFT_DRAW_STRING

#endif  // ROCKEY_USER_SETUP_H