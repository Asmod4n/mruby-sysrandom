module Sysrandom
  # For some reason SecureRandom defaults to 16 bytes
  DEFAULT_LENGTH = 16

  class << self
    alias :random_bytes :buf

    def base64(n = DEFAULT_LENGTH)
      B64.encode(random_bytes(n)).chomp!
    end

    def hex(n = DEFAULT_LENGTH)
      __bin2hex(random_bytes(n))
    end
  end
end
