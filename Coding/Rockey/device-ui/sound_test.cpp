// 显式声音输出观测适配；执行生产非阻塞时序，不证明实机音量。
#include "authorization_sound.hpp"
#include <cassert>
#include <vector>
#include <cstdio>
static std::vector<uint16_t> tones;
static void observe(uint16_t frequency){tones.push_back(frequency);}
int main(){
  rockey::sound::Player p(observe);
  p.request(true,0);p.request(false,1);
  p.poll(99);assert(tones==std::vector<uint16_t>{1700});
  p.poll(100);p.poll(180);p.poll(280);p.poll(360);p.poll(425);
  assert((tones==std::vector<uint16_t>{1700,0,2300,0,2600,0}));
  tones.clear();p.stop();tones.clear();
  p.request(false,0);p.request(true,1);p.cancel(false);p.poll(2);
  assert((tones==std::vector<uint16_t>{2600,0,1700}));
  p.cancel(false);p.poll(102);p.poll(182);
  assert(tones.back()==2300); // 关闭自动提示不会取消正在播放的人工双声。
  p.cancel(true);assert(tones.back()==0);
  puts("Sound: single/double patterns, deadlines and independent cancellation passed.");
}
