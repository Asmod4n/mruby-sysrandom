#include <mruby.h>
#include <mruby/string.h>
#include <mruby/data.h>

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

void
mrb_mruby_sysrandom_gem_init(mrb_state* mrb)
{
  struct RClass *sysrandom_mod = mrb_define_class(mrb, "Sysrandom", mrb->object_class);

  mrb_define_module_function(mrb, sysrandom_mod, "random",  mrb_randombytes_sysrandom,   MRB_ARGS_OPT(1));
  mrb_define_module_function(mrb, sysrandom_mod, "uniform", mrb_randombytes_sysrandom_uniform,  MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, sysrandom_mod, "buf",     mrb_randombytes_sysrandom_buf,      MRB_ARGS_OPT(2));
}

void mrb_mruby_sysrandom_gem_final(mrb_state* mrb) {}
