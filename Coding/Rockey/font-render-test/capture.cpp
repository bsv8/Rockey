#include "framebuffer.hpp"
int main(int argc,char** argv) {
  if(argc!=5)return 2;
  const auto role=static_cast<rockey::FontRole>(std::atoi(argv[1]));
  rockey::Display::Init();
  rockey::Rect clip{0,0,320,240};
  if(std::atoi(argv[4]))clip={15,23,42,15};
  int width = 0;
  if (std::strcmp(argv[1], "boot") == 0) {
    rockey::ui::DrawBootPoster();
  } else if (std::strcmp(argv[1], "pin") == 0) {
    rockey::ui::DrawPinRow(6, std::atoi(argv[4]), std::atoi(argv[2]), "123456", 50);
  } else {
    width=rockey::Display::DrawText(role,10,20,argv[2],std::strlen(argv[2]),65535,0,&clip);
    if(width!=rockey::Display::MeasureText(role,argv[2],std::strlen(argv[2])))return 3;
  }
  std::fprintf(stderr,"%d\n",width);
  FILE* file=std::fopen(argv[3],"wb");if(!file)return 4;
  if (std::strcmp(argv[1], "boot") == 0) {
    std::fprintf(file,"P6\n320 240\n255\n");
    for (uint16_t c : colors) {
      const unsigned char rgb[] = {static_cast<unsigned char>(((c >> 11) & 31) * 255 / 31),
        static_cast<unsigned char>(((c >> 5) & 63) * 255 / 63),
        static_cast<unsigned char>((c & 31) * 255 / 31)};
      std::fwrite(rgb, 1, 3, file);
    }
  } else {
    std::fprintf(file,"P5\n320 240\n255\n");
    std::fwrite(pixels.data(),1,pixels.size(),file);
  }
  std::fclose(file);
}
