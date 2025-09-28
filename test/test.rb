##
# Sysrandom full test suite (no floats expected)
#

# --- C-level bindings ---

assert('Sysrandom.random returns an Integer') do
  r = Sysrandom.random
  assert_kind_of Integer, r
end

assert('Sysrandom.uniform returns within range') do
  10.times do
    r = Sysrandom.uniform(100)
    assert_kind_of Integer, r
    assert_true r >= 0
    assert_true r < 100
  end
end

assert('Sysrandom.uniform raises on out of range') do
  assert_raise(RangeError) {
    Sysrandom.uniform(-1.0)
  }
end

assert('Sysrandom.buf with integer length') do
  s = Sysrandom.buf(32)
  assert_kind_of String, s
  assert_equal 32, s.bytesize
end

assert('Sysrandom.buf with string') do
  str = "abcd"
  Sysrandom.buf(str)
  assert_equal 4, str.bytesize
end

assert('Sysrandom.buf with false uses default length') do
  s = Sysrandom.buf(false)
  assert_equal Sysrandom::DEFAULT_LENGTH, s.bytesize
end

assert('Sysrandom.__bin2hex doubles length and is hex') do
  bin = "\x01\x02\xff"
  hex = Sysrandom.__bin2hex(bin)
  assert_equal bin.bytesize * 2, hex.bytesize
  ok = hex.each_byte.all? { |c|
    (c >= 48 && c <= 57) || (c >= 97 && c <= 102)
  }
  assert_true ok
end

assert('Sysrandom.buf raises TypeError on unsupported type') do
  assert_raise(TypeError) { Sysrandom.buf([]) }
end


# --- Ruby wrapper helpers ---

assert('Sysrandom.random_bytes is alias for buf') do
  s1 = Sysrandom.random_bytes(8)
  s2 = Sysrandom.buf(8)
  assert_equal 8, s1.bytesize
  assert_equal 8, s2.bytesize
end

assert('Sysrandom.hex returns hex string of correct length') do
  h = Sysrandom.hex(12)
  assert_equal 24, h.bytesize
  ok = h.each_byte.all? { |c|
    (c >= 48 && c <= 57) || (c >= 97 && c <= 102)
  }
  assert_true ok
end

assert('Sysrandom.hex default length') do
  h = Sysrandom.hex
  assert_equal Sysrandom::DEFAULT_LENGTH * 2, h.bytesize
end

assert('Sysrandom.base64 returns base64 string of correct length') do
  b = Sysrandom.base64(12)
  # base64 expands by 4/3, so length should be multiple of 4
  assert_equal 0, b.bytesize % 4
  ok = b.each_byte.all? { |c|
    (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || # A-Z, a-z
    (c >= 48 && c <= 57) || c == 43 || c == 47 || c == 61 # 0-9, +, /, =
  }
  assert_true ok
end

assert('Sysrandom.base64 default length') do
  b = Sysrandom.base64
  assert_true b.bytesize > 0
end
