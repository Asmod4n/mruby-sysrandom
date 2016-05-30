#include <mruby.h>
#include <mruby/string.h>
#include <mruby/data.h>
#include <stdlib.h>
#include <mruby/numeric.h>

#if (__GNUC__ >= 3) || (__INTEL_COMPILER >= 800) || defined(__clang__)
# define likely(x) __builtin_expect(!!(x), 1)
# define unlikely(x) __builtin_expect(!!(x), 0)
#else
# define likely(x) (x)
# define unlikely(x) (x)
#endif

/* How many bytes to generate by default, matching SecureRandom
 * Why SecureRandom has a default size argument is beyond me */
#define DEFAULT_N_BYTES 16

uint32_t __randombytes_sysrandom(void);
void __randombytes_sysrandom_buf(void * const buf, const size_t size);

/*
 * __randombytes_sysrandom_uniform() derives from OpenBSD's arc4random_uniform()
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 */
uint32_t
__randombytes_sysrandom_uniform(const uint32_t upper_bound)
{
    uint32_t min;
    uint32_t r;

    if (upper_bound < 2) {
        return 0;
    }
    min = (uint32_t) (-upper_bound % upper_bound);
    do {
        r = __randombytes_sysrandom();
    } while (r < min);

    return r % upper_bound;
}

/* Derived from original code by CodesInChaos */
char *
__sysrandom_bin2hex(char * const hex, const size_t hex_maxlen,
               const unsigned char * const bin, const size_t bin_len)
{
    size_t       i = (size_t) 0U;
    unsigned int x;
    int          b;
    int          c;

    if (bin_len >= SIZE_MAX / 2 || hex_maxlen <= bin_len * 2U) {
        abort(); /* LCOV_EXCL_LINE */
    }
    while (i < bin_len) {
        c = bin[i] & 0xf;
        b = bin[i] >> 4;
        x = (unsigned char) (87U + c + (((c - 10U) >> 8) & ~38U)) << 8 |
            (unsigned char) (87U + b + (((b - 10U) >> 8) & ~38U));
        hex[i * 2U] = (char) x;
        x >>= 8;
        hex[i * 2U + 1U] = (char) x;
        i++;
    }
    hex[i * 2U] = 0U;

    return hex;
}

static mrb_value
mrb_randombytes_sysrandom(mrb_state *mrb, mrb_value self)
{
  mrb_bool limit = FALSE;

  mrb_get_args(mrb, "|b", &limit);

#ifdef MRB_INT64
  return mrb_fixnum_value(__randombytes_sysrandom());
#else
  if (limit) {
    return mrb_fixnum_value(__randombytes_sysrandom_uniform(MRB_INT_MAX));
  } else {
    uint32_t ran = __randombytes_sysrandom();
    if (MRB_INT_MAX < ran ) {
      return mrb_float_value(mrb, ran);
    } else {
      return mrb_fixnum_value(ran);
    }
  }
#endif
}

static mrb_value
mrb_randombytes_sysrandom_uniform(mrb_state *mrb, mrb_value self)
{
  mrb_float upper_bound;

  mrb_get_args(mrb, "f", &upper_bound);

  if (upper_bound >= 0 && upper_bound <= UINT32_MAX) {
    uint32_t ran = __randombytes_sysrandom_uniform((uint32_t) upper_bound);
#ifndef MRB_INT64
    if (ran > MRB_INT_MAX) {
      return mrb_float_value(mrb, ran);
    }
    else
#endif
      return mrb_fixnum_value(ran);
  } else {
    mrb_raise(mrb, E_RANGE_ERROR, "upper_bound is out of range");
  }
}

static mrb_value
mrb_randombytes_sysrandom_buf(mrb_state *mrb, mrb_value self)
{
  mrb_value buf_obj = mrb_nil_value();
  mrb_int len;
  mrb_bool len_given = FALSE;

  mrb_get_args(mrb, "|oi?", &buf_obj, &len, &len_given);

  switch(mrb_type(buf_obj)) {
    case MRB_TT_FIXNUM: {
      len = mrb_fixnum(buf_obj);
      if (unlikely(len < 0||len > SIZE_MAX)) {
        mrb_raise(mrb, E_RANGE_ERROR, "size is out of range");
      }
      buf_obj = mrb_str_new(mrb, NULL, len);
      __randombytes_sysrandom_buf(RSTRING_PTR(buf_obj), len);
    } break;
    case MRB_TT_STRING:
      mrb_str_modify(mrb, RSTRING(buf_obj));
      __randombytes_sysrandom_buf(RSTRING_PTR(buf_obj), RSTRING_LEN(buf_obj));
      break;
    case MRB_TT_DATA: {
      if (likely(!len_given)) {
        mrb_value size_val = mrb_funcall(mrb, buf_obj, "size", 0);
        len = mrb_int(mrb, size_val);
      }

      if (unlikely(len < 0||len > SIZE_MAX)) {
        mrb_raise(mrb, E_RANGE_ERROR, "size is out of range");
      }

      __randombytes_sysrandom_buf(DATA_PTR(buf_obj), len);
    } break;
    case MRB_TT_CPTR: {
      if (unlikely(!len_given)) {
        mrb_raise(mrb, E_ARGUMENT_ERROR, "len missing");
      }

      if (unlikely(len < 0||len > SIZE_MAX)) {
        mrb_raise(mrb, E_RANGE_ERROR, "size is out of range");
      }

      __randombytes_sysrandom_buf(mrb_cptr(buf_obj), len);
    } break;
    case MRB_TT_FALSE:
      buf_obj = mrb_str_new(mrb, NULL, DEFAULT_N_BYTES);
      __randombytes_sysrandom_buf(RSTRING_PTR(buf_obj), DEFAULT_N_BYTES);
      break;
    default:
      mrb_raise(mrb, E_TYPE_ERROR, "only works with Strings, Data or cptr Types");
  }

  return buf_obj;
}

static mrb_value
mrb_sysrandom_bin2hex(mrb_state *mrb, mrb_value self)
{
  char *bin;
  mrb_int bin_len;

  mrb_get_args(mrb, "s", &bin, &bin_len);

  mrb_int hex_len;
  if(unlikely(mrb_int_mul_overflow(bin_len, 2, &hex_len))) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "bin_len is too large");
  }

  mrb_value hex = mrb_str_new(mrb, NULL, hex_len);

  char *h = __sysrandom_bin2hex(RSTRING_PTR(hex), RSTRING_LEN(hex) + 1,
    (const unsigned char *) bin, bin_len);
  assert(h);

  return hex;
}

void
mrb_mruby_sysrandom_gem_init(mrb_state* mrb)
{
  struct RClass *sysrandom_mod = mrb_define_module(mrb, "Sysrandom");

  mrb_define_module_function(mrb, sysrandom_mod, "random",  mrb_randombytes_sysrandom,   MRB_ARGS_OPT(1));
  mrb_define_module_function(mrb, sysrandom_mod, "uniform", mrb_randombytes_sysrandom_uniform,  MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, sysrandom_mod, "buf",     mrb_randombytes_sysrandom_buf,      MRB_ARGS_OPT(2));
  mrb_define_module_function(mrb, sysrandom_mod, "__bin2hex", mrb_sysrandom_bin2hex,  MRB_ARGS_REQ(1));
}

void mrb_mruby_sysrandom_gem_final(mrb_state* mrb) {}
