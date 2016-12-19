#pragma once
#include <fnd/types.h>

struct sCtrTmdPlatormReservedRegion
{
private:
	u32 public_save_size_;
	u32 private_save_size_;
	u8 reserved1_[4];
	u8 srl_flag_;
	u8 reserved2_[0x31];
public:
	u32 public_save_data_size() const { return le_word(public_save_size_); }
	u32 private_save_data_size() const { return le_word(private_save_size_); }
	u8 srl_flag() const { return srl_flag_; }

	void clear() { memset(this, 0, sizeof(sCtrTmdPlatormReservedRegion)); }

	void set_public_save_data_size(u32 size) { public_save_size_ = le_word(size); }
	void set_private_save_data_size(u32 size) { private_save_size_ = le_word(size); }
	void set_srl_flag(u8 flag) { srl_flag_ = flag; }
};