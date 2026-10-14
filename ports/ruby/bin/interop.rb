# frozen_string_literal: true

# The interop program for ports/conformance/interop.py (spec/PORTING.md, "The interop program"):
# ruby bin/interop.rb URL AGENT_IDS SECONDS, the ingest token in SMARTWATCH_INGEST_TOKEN.
require_relative '../lib/smartwatch'

abort 'usage: ruby bin/interop.rb URL AGENT_IDS SECONDS' unless ARGV.size == 3
url = ARGV[0]
ids = ARGV[1].split(',')
seconds = Integer(ARGV[2])
token = ENV.fetch('SMARTWATCH_INGEST_TOKEN', nil)
$stdout.sync = true
out = Mutex.new

pollers = ids.map do |a|
  SmartWatch::CommandPoller.new(SmartWatch::Client.new(url, token), a, interval: 0.2) do |cmd|
    out.synchronize { puts "RESET #{a} #{cmd['reset_id']}" }
  end.start
end
rep = SmartWatch::Reporter.new(url, token).start
t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
(seconds * 10).times do |r|
  ids.each { |a| ids.each { |b| rep.record(a, b, 1) unless a == b } }
  left = t0 + (r + 1) * 0.1 - Process.clock_gettime(Process::CLOCK_MONOTONIC)
  sleep(left) if left.positive?
end
rep.close
out.synchronize { puts "SENT #{rep.sent}" }
begin
  $stdin.read
rescue StandardError
  nil
end
pollers.each(&:stop)
