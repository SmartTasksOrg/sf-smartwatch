# SmartWatch for Ruby: the engine, a reporter and a command poller. Not published on RubyGems; use it from a
# clone (ruby -Ilib).
Gem::Specification.new do |s|
  s.name = 'sf-smartwatch'
  s.version = '0.1.0'
  s.summary = 'SmartWatch for Ruby: the coupling-density engine, a reporter and a command poller for the Python monitor.'
  s.license = 'Apache-2.0'
  s.authors = ['SmartTasks Lab']
  s.files = Dir['lib/**/*']
  s.required_ruby_version = '>= 3.2'
  s.metadata['allowed_push_host'] = 'https://example.invalid' # not published: refuse `gem push`
end
