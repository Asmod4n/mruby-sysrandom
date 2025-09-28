#include <mruby.h>
#include <mruby/string.h>
#include <mruby/data.h>
#include <stdint.h>
#include <stdlib.h>
#include <mruby/numeric.h>
#include <mruby/sysrandom.h>
#include <assert.h>
#include <mruby/num_helpers.h>
#include <mruby/presym.h>
#include <mruby/class.h>

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

static mrb_value
mrb_randombytes_sysrandom(mrb_state *mrb, mrb_value self)
{
  mrb_bool limit = FALSE;

  mrb_get_args(mrb, "|b", &limit);

  return mrb_convert_uint32(mrb, mrb_sysrandom());
}

static mrb_value
mrb_randombytes_sysrandom_uniform(mrb_state *mrb, mrb_value self)
{
  mrb_int upper_bound;
  mrb_get_args(mrb, "i", &upper_bound);

  if (unlikely(upper_bound < 0)) {
    mrb_raisef(mrb, E_RANGE_ERROR,
               "upper_bound must be non‑negative (got %S)",
               mrb_int_value(mrb, upper_bound));
  }
  if (unlikely(upper_bound > UINT32_MAX)) {
    mrb_raisef(mrb, E_RANGE_ERROR,
               "upper_bound too large (got %S, maximum %S)",
               mrb_int_value(mrb, upper_bound),
               mrb_convert_uint32(mrb, UINT32_MAX));
  }

  return mrb_convert_uint32(mrb, mrb_sysrandom_uniform((uint32_t) upper_bound));
}

static mrb_value
mrb_randombytes_sysrandom_buf(mrb_state *mrb, mrb_value self)
{
  mrb_value buf_obj = mrb_nil_value();
  mrb_int len;
  mrb_bool len_given = FALSE;

  mrb_get_args(mrb, "|oi?", &buf_obj, &len, &len_given);

  switch (mrb_type(buf_obj)) {
    case MRB_TT_INTEGER: {
      len = mrb_integer(buf_obj);
      if (unlikely(len < 0 || len > SIZE_MAX)) {
        mrb_raisef(mrb, E_RANGE_ERROR,
                   "requested buffer size %S is invalid (must be between 0 and %S)",
                   mrb_int_value(mrb, len),
                   mrb_convert_size_t(mrb, SIZE_MAX));
      }
      buf_obj = mrb_str_new(mrb, NULL, len);
      mrb_sysrandom_buf(RSTRING_PTR(buf_obj), len);
    } break;
    case MRB_TT_STRING:
      mrb_str_modify(mrb, RSTRING(buf_obj));
      mrb_sysrandom_buf(RSTRING_PTR(buf_obj), RSTRING_LEN(buf_obj));
      break;
    case MRB_TT_DATA: {
      if (likely(!len_given)) {
        mrb_value size_val = mrb_funcall_id(mrb, buf_obj, MRB_SYM(bytesize), 0);
        len = mrb_int(mrb, size_val);
      }
      if (unlikely(len < 0 || len > SIZE_MAX)) {
        mrb_raisef(mrb, E_RANGE_ERROR,
                   "requested buffer size %S is invalid (must be between 0 and %S)",
                   mrb_int_value(mrb, len),
                   mrb_convert_size_t(mrb, SIZE_MAX));
      }
      mrb_sysrandom_buf(DATA_PTR(buf_obj), len);
    } break;
    case MRB_TT_CPTR: {
      if (unlikely(!len_given)) {
        mrb_raise(mrb, E_ARGUMENT_ERROR,
                  "when passing a cptr, you must also provide a length");
      }
      if (unlikely(len < 0 || len > SIZE_MAX)) {
        mrb_raisef(mrb, E_RANGE_ERROR,
                   "requested buffer size %S is invalid (must be between 0 and %S)",
                   mrb_int_value(mrb, len),
                   mrb_convert_size_t(mrb, SIZE_MAX));
      }
      mrb_sysrandom_buf(mrb_cptr(buf_obj), len);
    } break;
    case MRB_TT_FALSE:
      buf_obj = mrb_str_new(mrb, NULL, DEFAULT_N_BYTES);
      mrb_sysrandom_buf(RSTRING_PTR(buf_obj), DEFAULT_N_BYTES);
      break;
    default:
    mrb_raisef(mrb, E_TYPE_ERROR,
              "Sysrandom.buf only accepts Integer, String, Data, cptr, or false (got %S)",
              mrb_str_new_cstr(mrb, mrb_obj_classname(mrb, buf_obj)));

  }

  return buf_obj;
}

static mrb_value
_mrb_sysrandom_bin2hex(mrb_state *mrb, mrb_value self)
{
  char *bin;
  mrb_int bin_len;
  mrb_get_args(mrb, "s", &bin, &bin_len);

  mrb_value hex_len = mrb_num_mul(mrb, mrb_int_value(mrb, bin_len), mrb_int_value(mrb, 2));
  if (unlikely(mrb_float_p(hex_len))) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR,
               "binary string length %S is too large to convert to hex",
               mrb_int_value(mrb, bin_len));
  }

  mrb_value hex = mrb_str_new(mrb, NULL, mrb_integer(hex_len));
  char *h = mrb_sysrandom_bin2hex(RSTRING_PTR(hex), RSTRING_CAPA(hex) + 1,
                                  (const unsigned char *)bin, bin_len);
  assert(h);
  return hex;
}

void
mrb_mruby_sysrandom_gem_init(mrb_state* mrb)
{
  struct RClass *sysrandom_mod = mrb_define_module_id(mrb, MRB_SYM(Sysrandom));

  mrb_define_module_function_id(mrb, sysrandom_mod, MRB_SYM(random),  mrb_randombytes_sysrandom,   MRB_ARGS_OPT(1));
  mrb_define_module_function_id(mrb, sysrandom_mod, MRB_SYM(uniform), mrb_randombytes_sysrandom_uniform,  MRB_ARGS_REQ(1));
  mrb_define_module_function_id(mrb, sysrandom_mod, MRB_SYM(buf),     mrb_randombytes_sysrandom_buf,      MRB_ARGS_OPT(2));
  mrb_define_module_function_id(mrb, sysrandom_mod, MRB_SYM(__bin2hex), _mrb_sysrandom_bin2hex,  MRB_ARGS_REQ(1));
}

void mrb_mruby_sysrandom_gem_final(mrb_state* mrb) {}
