MRuby::Gem::Specification.new('mruby-sysrandom') do |spec|
  spec.license = 'ISC'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'Secure random number generation for mruby'
  spec.add_dependency 'mruby-b64'
end
