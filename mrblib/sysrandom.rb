module Sysrandom
  # For some reason SecureRandom defaults to 16 bytes
  DEFAULT_LENGTH = 16

  class << self
    alias_method :random_bytes, :buf

    def base64(n = DEFAULT_LENGTH)
      B64.encode(buf(n)).chomp!
    end

    def hex(n = DEFAULT_LENGTH)
      __bin2hex(buf(n))
    end
  end
end
