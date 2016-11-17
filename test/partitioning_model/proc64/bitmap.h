/*
 * Copyright (C) 2015 David Devecsery
 */

#ifndef INCLUDE_UTIL_H_
#define INCLUDE_UTIL_H_


#include <array>
#include <bitset>
#include <limits>
#include <memory>

// Paged Bitmap {{{
template<size_t max_size = (1LL<<32),
  uint32_t page_size_bits = 4096>
class PagedBitmap {
 public:
  const static uint32_t NumPages =
    static_cast<uint32_t>(max_size / page_size_bits);

  void reset(uint32_t bit) {
    // Should just be shift after opt
    uint32_t page_num = bit / page_size_bits;

    auto &pmap = pages_[page_num];
    if (pmap == nullptr) {
	return;
    }

    uint32_t bit_num = bit % page_size_bits;

    pmap->reset(bit_num);
    
  }
 
 void clear() {
     for (auto &pmap : pages_) {
	 pmap.reset(nullptr);
     }
 }




  bool test(uint32_t bit) const {
    uint32_t page_num = bit / page_size_bits;
    auto &pmap = pages_[page_num];

    if (pmap == nullptr) {
      return false;
    }

    uint32_t bit_num = bit % page_size_bits;

    return pmap->test(bit_num);
  }

  // Returns true if set operation successful
  bool testAndSet(uint32_t bit) {
    uint32_t page_num = bit / page_size_bits;
    auto &pmap = pages_[page_num];

    if (pmap == nullptr) {
      pmap.reset(new std::bitset<page_size_bits>);
    }

    uint32_t bit_num = bit % page_size_bits;

    bool ret = pmap->test(bit_num);
    pmap->set(bit_num);

    return !ret;
  }

  void set(uint32_t bit) {
    uint32_t page_num = bit / page_size_bits;
    auto &pmap = pages_[page_num];

    if (pmap == nullptr) {
      pmap.reset(new std::bitset<page_size_bits>);
    }

    uint32_t bit_num = bit % page_size_bits;

    pmap->set(bit_num);
  }

 private:
  std::array<std::unique_ptr<std::bitset<page_size_bits>>, NumPages> pages_;
};
//}}}
#endif /* INCLUDE_UTIL_H_*/
