Pod::Spec.new do |s|
  s.name         = "sr25519.c"
  s.version      = "0.1.0"
  s.summary      = "iOS bindings for sr25519 rust implementation"
  s.homepage     = "https://github.com/novasamatech/sr25519.c"
  s.license      = 'MIT'
  s.author       = {'Ruslan Rezin' => 'ruslan@novasama.io'}
  s.source       = { :git => 'https://github.com/novasamatech/sr25519.c',  :tag => "#{s.version}"}

  s.ios.deployment_target = '12.0'
  s.swift_version = '5.0'

  s.vendored_frameworks = 'bindings/xcframework/sr25519.c.xcframework'
  s.module_name = 'sr25519.c'
end