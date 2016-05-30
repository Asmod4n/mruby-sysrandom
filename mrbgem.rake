MRuby::Gem::Specification.new('mruby-sysrandom') do |spec|
  spec.license = 'ISC'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'Secure Random Numbers for mruby'
  spec.add_dependency 'mruby-b64'
end
