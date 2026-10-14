# frozen_string_literal: true

# ruby bin/conformance.rb DIR: runs spec/conformance/*.json against the Ruby port, as the Python runner does.
require_relative '../lib/smartwatch'

dir = ARGV[0] || File.join(__dir__, '..', '..', '..', 'spec', 'conformance')
load_v = ->(n) { JSON.parse(File.read(File.join(dir, n), encoding: 'UTF-8')) }
c = lambda do |v|
  SmartWatch.canonical(v)
rescue SmartWatch::CanonicalError => e
  "<not canonical: #{e.message}>"
end
total = 0
fails = []
check = lambda do |name, got, want|
  total += 1
  g = c.(got)
  w = c.(want)
  fails << "#{name}: got #{g[0, 300]}, want #{w[0, 300]}" unless g == w
end
pick = ->(cs, keys) { cs.slice(*keys) }
expand = ->(items) { items.is_a?(Hash) ? (items['from']...items['to']).map { |i| "#{items['prefix']}#{i}" } : items }

load_v.('canonical.json')['cases'].each do |cs|
  text = c.(cs['input'])
  check.("canonical/#{cs['name']}", [text, SmartWatch.sha256_hex(text)], [cs['canonical'], cs['sha256']])
end

load_v.('hashing.json')['cases'].each_with_index do |cs, i|
  h64 = SmartWatch.fnv1a64(cs['seed'], cs['text'])
  got = { 'fnv1a32' => SmartWatch.fnv1a32(cs['seed'], cs['text']), 'fnv1a64' => h64.to_s, 'mix64' => SmartWatch.mix64(h64).to_s,
          'bucket' => SmartWatch.bucket(cs['seed'], cs['text']) }
  check.("hashing/#{i}", got, pick.(cs, got.keys))
end

load_v.('hll.json')['cases'].each do |cs|
  h = SmartWatch::HyperLogLog.new(cs['seed'])
  expand.(cs['items']).each { |x| h.add(x) }
  check.("hll/#{cs['name']}", { 'estimate' => h.estimate, 'digest' => h.digest }, pick.(cs, %w[estimate digest]))
end

load_v.('density.json')['cases'].each_with_index do |cs, i|
  check.("density/#{i}", SmartWatch.density_micro(cs['messages'], cs['possible_pairs'], cs['window_ms']), cs['density_micro'])
end

load_v.('policies.json')['cases'].each do |cs|
  got = begin
    SmartWatch.validate_policy(cs['policy'])
    { 'ok' => true }
  rescue SmartWatch::WatchError => e
    { 'ok' => false, 'code' => e.code }
  end
  check.("policies/#{cs['name']}", got, pick.(cs, %w[ok code]))
end

load_v.('calibration.json')['cases'].each do |cs|
  got = begin
    { 'ok' => true, 'thresholds' => SmartWatch.thresholds(cs['densities'], cs['permille']) }
  rescue ArgumentError
    { 'ok' => false }
  end
  check.("calibration/#{cs['name']}", got, pick.(cs, %w[ok thresholds]))
end

load_v.('monitor.json')['cases'].each do |cs|
  eng = SmartWatch::Engine.new(cs['policy'])
  cs['steps'].each_with_index do |st, i|
    got = begin
      case st['op']
      when 'add' then { 'ok' => true, 'outputs' => eng.add(st['src'], st['dst'], st['ts_ms'], st['count']) }
      when 'flush' then { 'ok' => true, 'outputs' => eng.flush(st['now_ms']) }
      else eng.snapshot
      end
    rescue SmartWatch::WatchError => e
      { 'ok' => false, 'code' => e.code }
    end
    check.("monitor/#{cs['name']} step #{i} (#{st['op']})", got, st['expect'])
  end
end

load_v.('audit.json')['cases'].each do |cs|
  r = SmartWatch.verify_audit(cs['records'])
  check.("audit/#{cs['name']}", r.slice('ok', 'index'), cs['result'])
end

fails.each { |f| puts "FAIL #{f}" }
unless fails.empty?
  puts "ruby: #{fails.size} of #{total} vectors FAILED"
  exit 1
end
puts "ruby: #{total}/#{total} vectors passed"
