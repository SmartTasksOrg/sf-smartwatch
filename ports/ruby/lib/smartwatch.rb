# frozen_string_literal: true

# SmartWatch for Ruby (spec/SEMANTICS.md, spec/PORTING.md): canonical JSON, seeded FNV-1a and mix64,
# HyperLogLog, density, policy validation, calibration, the engine, audit chain verification, and the agent
# side (a Reporter and a CommandPoller that talk to the Python monitor over HTTP).
#
# Documents are what JSON.parse returns (Hash, Array, Integer, Float, String, true, false, nil); only Integer
# counts as an integer, so 1.5, true and "1" are refused where one is required. Engine outputs are Hashes with
# String keys.
require 'json'
require 'digest'
require 'net/http'
require 'openssl'
require 'uri'

module SmartWatch
  MAX_INT = 2**53 - 1
  MAX_COUNT = 1_000_000_000
  BUCKETS = 1 << 20
  MICRO = 1_000_000
  MAX_AGENTS = 100_000_000
  M32 = 0xFFFF_FFFF
  M64 = 0xFFFF_FFFF_FFFF_FFFF
  GENESIS = ('0' * 64).freeze
  ID = %r{\A[A-Za-z0-9._:@/-]{1,128}\z}
  LEVEL_NAME = /\A[a-z][a-z0-9_-]{0,31}\z/
  POLICY_FIELDS = %w[schema environment window_ms late_windows max_empty_windows min_agents levels hysteresis_permille
                     reset limits hash_seed].sort.freeze
  RESET_FIELDS = %w[level sustain_ms mode confirm_timeout_ms on_timeout cooldown_ms max_agents hot_pair_min_count].sort.freeze
  LIMIT_FIELDS = %w[max_pairs_exact max_agents_exact top_k candidates].sort.freeze
  PROFILES = { 'prod' => [950, 990, 999], 'staging' => [900, 950, 990] }.freeze

  # A refused input; +code+ is the stable WATCH-* code (WATCH-BAD-EVENT, WATCH-BAD-POLICY).
  class WatchError < ArgumentError
    attr_reader :code

    def initialize(code, message = '')
      super(message.empty? ? code : "#{code}: #{message}")
      @code = code
    end
  end

  # A value with no canonical form (a float, a non-ASCII key, text that is not valid UTF-8, another type).
  class CanonicalError < ArgumentError; end

  # ---------------------------------------------------------------- canonical JSON

  ESCAPES = { '"' => '\\"', '\\' => '\\\\', "\b" => '\\b', "\f" => '\\f', "\n" => '\\n', "\r" => '\\r', "\t" => '\\t' }.freeze

  def self.canon_str(s)
    s = s.dup.force_encoding(Encoding::UTF_8) unless s.encoding == Encoding::UTF_8
    raise CanonicalError, 'canonical JSON strings must be valid UTF-8' unless s.valid_encoding?

    body = s.gsub(/["\\\x00-\x1f]/) { |ch| ESCAPES[ch] || format('\\u%04x', ch.ord) }
    "\"#{body}\""
  end

  # Canonical JSON text (SEMANTICS.md section 8), UTF-8. Raises CanonicalError.
  def self.canonical(v)
    case v
    when nil then 'null'
    when true then 'true'
    when false then 'false'
    when Integer then v.to_s
    when String then canon_str(v)
    when Array then "[#{v.map { |x| canonical(x) }.join(',')}]"
    when Hash
      v.each_key { |k| raise CanonicalError, 'object keys must be ASCII strings' unless k.is_a?(String) && k.ascii_only? }
      "{#{v.keys.sort.map { |k| "#{canon_str(k)}:#{canonical(v[k])}" }.join(',')}}"
    when Float then raise CanonicalError, 'canonical JSON allows integers only'
    else raise CanonicalError, "canonical JSON cannot encode #{v.class}"
    end
  end

  def self.sha256_hex(bytes) = Digest::SHA256.hexdigest(bytes)

  # ---------------------------------------------------------------- hashes

  def self.seeded(seed, text) = seed.b + "\x00".b + text.b

  # FNV-1a 32 over UTF-8(seed) || 0x00 || UTF-8(text).
  def self.fnv1a32(seed, text)
    h = 2_166_136_261
    seeded(seed, text).each_byte { |b| h = ((h ^ b) * 16_777_619) & M32 }
    h
  end

  # FNV-1a 64 over the same bytes. The prime is 2^40 + 0x1b3; the state is kept in two 32-bit halves so that
  # every intermediate value stays a small Integer (no Bignum in the loop).
  def self.fnv1a64(seed, text)
    hi = 0xcbf29ce4
    lo = 0x84222325
    seeded(seed, text).each_byte do |b|
      lo ^= b
      t = lo * 0x1b3
      hi = (hi * 0x1b3 + (t >> 32) + (lo << 8)) & M32
      lo = t & M32
    end
    (hi << 32) | lo
  end

  # MurmurHash3 fmix64 (modulo 2^64).
  def self.mix64(h)
    h ^= h >> 33
    h = (h * 0xFF51AFD7ED558CCD) & M64
    h ^= h >> 33
    h = (h * 0xC4CEB9FE1A85EC53) & M64
    h ^ (h >> 33)
  end

  # A pair's bucket: fnv1a32(seed, text) mod 2^20.
  def self.bucket(seed, text) = fnv1a32(seed, text) & (BUCKETS - 1)

  # ---------------------------------------------------------------- HyperLogLog

  # HyperLogLog, p = 14 (SEMANTICS.md section 5).
  class HyperLogLog
    P = 14
    M = 1 << P
    MAXRHO = 64 - P + 1
    ALPHA = 0.7213 / (1 + 1.079 / M)
    W_MASK = (1 << (64 - P)) - 1

    def initialize(seed)
      @seed = seed
      @reg = Array.new(M, 0)
    end

    def add(item)
      h = SmartWatch.mix64(SmartWatch.fnv1a64(@seed, item))
      j = h >> (64 - P)
      rho = MAXRHO - (h & W_MASK).bit_length
      @reg[j] = rho if rho > @reg[j]
    end

    def estimate
      counts = Array.new(MAXRHO + 1, 0)
      @reg.each { |r| counts[r] += 1 }
      z = 0.0
      MAXRHO.downto(0) { |v| z += counts[v] * (2.0**-v) if counts[v].positive? }
      e = ALPHA * M * M / z
      zeros = counts[0]
      e = M * Math.log(M.to_f / zeros) if e <= 2.5 * M && zeros.positive?
      [(e + 0.5).floor, MAX_INT].min
    end

    # Lower-case hex SHA-256 of the 16,384 register bytes.
    def digest = SmartWatch.sha256_hex(@reg.pack('C*'))
  end

  # ---------------------------------------------------------------- density, policy, calibration

  # min(2^53 - 1, floor((double(messages) * 1e9) / (double(possible) * double(window_ms)))), 0 without pairs.
  def self.density_micro(messages, possible_pairs, window_ms)
    return 0 if possible_pairs <= 0

    [((messages.to_f * 1e9) / (possible_pairs.to_f * window_ms.to_f)).floor, MAX_INT].min
  end

  # min(2^53 - 1, a + b).
  def self.sat(a, b) = [MAX_INT, a + b].min

  def self.int_in?(v, lo, hi) = v.is_a?(Integer) && v >= lo && v <= hi
  def self.id?(v) = v.is_a?(String) && v.ascii_only? && ID.match?(v)
  def self.exactly?(o, fields) = o.is_a?(Hash) && o.keys.sort == fields

  # Check a parsed policy document; returns it or raises WatchError('WATCH-BAD-POLICY').
  def self.validate_policy(doc)
    bad = ->(m) { raise WatchError.new('WATCH-BAD-POLICY', m) }
    bad.("the policy must have exactly the fields #{POLICY_FIELDS.join(', ')}") unless exactly?(doc, POLICY_FIELDS)
    bad.('schema must be "smartwatch.policy/v1"') unless doc['schema'] == 'smartwatch.policy/v1'
    bad.('environment must match [A-Za-z0-9._:@/-]{1,128}') unless id?(doc['environment'])
    [['window_ms', 100, 60_000], ['late_windows', 0, 60], ['max_empty_windows', 0, 3600], ['min_agents', 2, 1_000_000],
     ['hysteresis_permille', 0, 900]].each do |k, lo, hi|
      bad.("#{k} must be an integer from #{lo} to #{hi}") unless int_in?(doc[k], lo, hi)
    end
    lv = doc['levels']
    bad.('levels must be a list of 1 to 8 levels') unless lv.is_a?(Array) && lv.size.between?(1, 8)
    names = {}
    prev = 0
    lv.each do |x|
      bad.('each level must be {"name", "min_density_micro"}') unless exactly?(x, %w[min_density_micro name])
      n = x['name']
      unless n.is_a?(String) && n.ascii_only? && LEVEL_NAME.match?(n) && n != 'normal' && !names.key?(n)
        bad.('level names must match [a-z][a-z0-9_-]{0,31}, be unique and not "normal"')
      end
      unless int_in?(x['min_density_micro'], 1, MAX_INT) && x['min_density_micro'] > prev
        bad.('min_density_micro must be a positive integer, strictly increasing from level to level')
      end
      names[n] = true
      prev = x['min_density_micro']
    end
    r = doc['reset']
    bad.("reset must have exactly the fields #{RESET_FIELDS.join(', ')}") unless exactly?(r, RESET_FIELDS)
    bad.('reset.level must be one of the level names') unless r['level'].is_a?(String) && names.key?(r['level'])
    bad.('reset.mode must be auto, confirm or off') unless %w[auto confirm off].include?(r['mode'])
    bad.('reset.on_timeout must be reset or cancel') unless %w[reset cancel].include?(r['on_timeout'])
    [['sustain_ms', 0, 3_600_000], ['confirm_timeout_ms', 0, 3_600_000], ['cooldown_ms', 0, 86_400_000], ['max_agents', 1, 1000],
     ['hot_pair_min_count', 1, 1_000_000_000]].each do |k, lo, hi|
      bad.("reset.#{k} must be an integer from #{lo} to #{hi}") unless int_in?(r[k], lo, hi)
    end
    li = doc['limits']
    bad.("limits must have exactly the fields #{LIMIT_FIELDS.join(', ')}") unless exactly?(li, LIMIT_FIELDS)
    [['max_pairs_exact', 1, 10_000_000], ['max_agents_exact', 1, 10_000_000], ['top_k', 1, 100], ['candidates', 1, 65_536]].each do |k, lo, hi|
      bad.("limits.#{k} must be an integer from #{lo} to #{hi}") unless int_in?(li[k], lo, hi)
    end
    seed = doc['hash_seed']
    unless seed.is_a?(String) && seed.dup.force_encoding(Encoding::UTF_8).valid_encoding? && seed.bytesize.between?(1, 256)
      bad.('hash_seed must be a string of 1 to 256 bytes')
    end
    doc
  end

  # Read and validate a policy file (WatchError when invalid or not JSON).
  def self.load_policy(path)
    doc = begin
      JSON.parse(File.read(path, encoding: 'UTF-8'))
    rescue JSON::ParserError => e
      raise WatchError.new('WATCH-BAD-POLICY', "#{path}: not JSON (#{e.message})")
    end
    validate_policy(doc)
  end

  # Calibration thresholds (SEMANTICS.md section 7). ArgumentError when densities is empty, a density is not an
  # integer >= 0, or a percentile is not an integer from 1 to 1000.
  def self.thresholds(densities, permille)
    raise ArgumentError, 'densities are integers >= 0' unless densities.all? { |d| d.is_a?(Integer) && d >= 0 }

    xs = densities.sort
    raise ArgumentError, 'no densities to calibrate from' if xs.empty?

    prev = 0
    permille.map do |p|
      raise ArgumentError, 'percentiles are integers from 1 to 1000 (permille)' unless int_in?(p, 1, 1000)

      rank = (p * xs.size + 999) / 1000
      v = [xs[[rank, 1].max - 1], prev + 1, 1].max
      prev = v
    end
  end

  # ---------------------------------------------------------------- engine

  # A binary min-heap of [estimate, pair text]; "a\nb" orders as (a, b) since "\n" is below every id byte.
  class CandHeap
    def initialize = @a = []
    def size = @a.size
    def top = @a[0]

    def self.less?(x, y) = x[0] < y[0] || (x[0] == y[0] && x[1] < y[1])

    def push(x)
      a = @a
      a << x
      i = a.size - 1
      while i.positive?
        p = (i - 1) / 2
        break unless CandHeap.less?(a[i], a[p])

        a[i], a[p] = a[p], a[i]
        i = p
      end
    end

    def pop
      a = @a
      last = a.pop
      return last if a.empty?

      out = a[0]
      a[0] = last
      i = 0
      n = a.size
      loop do
        l = 2 * i + 1
        break if l >= n

        c = l + 1 < n && CandHeap.less?(a[l + 1], a[l]) ? l + 1 : l
        break unless CandHeap.less?(a[c], a[i])

        a[i], a[c] = a[c], a[i]
        i = c
      end
      out
    end
  end

  # One open window.
  class Window
    attr_accessor :pairs, :agents, :total, :self_messages, :buckets, :cand, :heap, :hll_pairs, :hll_agents,
                  :pairs_over, :agents_over

    def initialize
      @pairs = {}       # "a\nb" (a < b) => exact count
      @agents = {}      # id => true
      @total = 0
      @self_messages = 0
      @buckets = nil    # sparse Hash bucket => counter (a missing bucket is 0)
      @cand = {}        # "a\nb" => bucket estimate
      @heap = nil
      @hll_pairs = nil
      @hll_agents = nil
      @pairs_over = false
      @agents_over = false
    end
  end

  # Check an event (SEMANTICS.md section 2); raises WatchError('WATCH-BAD-EVENT').
  def self.check_event(src, dst, ts_ms, count)
    raise WatchError.new('WATCH-BAD-EVENT', 'src and dst must match [A-Za-z0-9._:@/-]{1,128}') unless id?(src) && id?(dst)
    raise WatchError.new('WATCH-BAD-EVENT', 'ts_ms must be an integer from 0 to 2^53 - 1') unless int_in?(ts_ms, 0, MAX_INT)
    raise WatchError.new('WATCH-BAD-EVENT', 'count must be an integer from 1 to 10^9') unless int_in?(count, 1, MAX_COUNT)
  end

  # The SmartWatch engine (SEMANTICS.md section 6). Deterministic: time comes from the events and from flush.
  # add and flush return the outputs of the windows they closed. Not thread-safe; callers synchronize.
  class Engine
    attr_reader :policy

    def initialize(policy)
      @policy = SmartWatch.validate_policy(policy)
      @window_ms = policy['window_ms']
      @late = policy['late_windows']
      @max_empty = policy['max_empty_windows']
      @seed = policy['hash_seed']
      @lim = policy['limits']
      @levels = policy['levels'].map { |l| [l['name'], l['min_density_micro']] }
      @reset = policy['reset']
      @reset_idx = @levels.index { |l| l[0] == @reset['level'] }
      @acc = {}
      @next_emit = nil
      @high = nil
      @empties = 0
      @level = -1
      @streak_start = nil
      @triggered = false
      @last_trigger = nil
      @events = @messages = @late_dropped = @skipped_windows = @windows = 0
    end

    def add(src, dst, ts_ms, count = 1)
      SmartWatch.check_event(src, dst, ts_ms, count)
      w = ts_ms / @window_ms
      if @next_emit.nil?
        @next_emit = w
        @high = w
      end
      if w < @next_emit
        @late_dropped = SmartWatch.sat(@late_dropped, count)
        return []
      end
      @events = SmartWatch.sat(@events, 1)
      @messages = SmartWatch.sat(@messages, count)
      count_into(@acc[w] ||= Window.new, src, dst, count)
      @high = w if w > @high
      close
    end

    def flush(now_ms)
      unless SmartWatch.int_in?(now_ms, 0, MAX_INT)
        raise WatchError.new('WATCH-BAD-EVENT', 'now_ms must be an integer from 0 to 2^53 - 1')
      end
      return [] if @next_emit.nil?

      w = now_ms / @window_ms
      @high = w if w > @high
      close
    end

    def snapshot
      { 'level' => name(@level), 'next_window' => @next_emit, 'open_windows' => @acc.size, 'events' => @events,
        'messages' => @messages, 'late_dropped' => @late_dropped, 'skipped_windows' => @skipped_windows, 'windows' => @windows }
    end

    private

    def count_into(a, src, dst, count)
      if src == dst
        a.self_messages = SmartWatch.sat(a.self_messages, count)
        return
      end
      a.total = SmartWatch.sat(a.total, count)
      [src, dst].each do |x|
        next if a.agents.key?(x)

        if a.agents_over
          a.hll_agents.add(x)
        elsif a.agents.size < @lim['max_agents_exact']
          a.agents[x] = true
        else
          a.agents_over = true
          a.hll_agents = HyperLogLog.new(@seed)
          a.agents.each_key { |y| a.hll_agents.add(y) }
          a.hll_agents.add(x)
        end
      end
      key = src < dst ? "#{src}\n#{dst}" : "#{dst}\n#{src}"
      if a.pairs.key?(key)
        a.pairs[key] = SmartWatch.sat(a.pairs[key], count)
        return
      end
      if !a.pairs_over && a.pairs.size < @lim['max_pairs_exact']
        a.pairs[key] = count
        return
      end
      unless a.pairs_over
        a.pairs_over = true
        a.hll_pairs = HyperLogLog.new(@seed)
        a.pairs.each_key { |k| a.hll_pairs.add(k) }
        a.buckets = Hash.new(0)
        a.heap = CandHeap.new
      end
      a.hll_pairs.add(key)
      i = SmartWatch.bucket(@seed, key)
      est = a.buckets[i] = SmartWatch.sat(a.buckets[i], count)
      cand = a.cand
      heap = a.heap
      if cand.key?(key) || cand.size < @lim['candidates']
        cand[key] = est
        heap.push([est, key])
      else
        heap.pop while cand[heap.top[1]] != heap.top[0]   # stale entries (estimates only grow)
        low_est, low_key = heap.top
        if est > low_est || (est == low_est && key > low_key)
          heap.pop
          cand.delete(low_key)
          cand[key] = est
          heap.push([est, key])
        end
      end
      return unless heap.size > 4 * cand.size + 64

      a.heap = CandHeap.new
      cand.each { |k, v| a.heap.push([v, k]) }
    end

    def close
      out = []
      while @next_emit + @late < @high
        w = @next_emit
        a = @acc.delete(w)
        if a
          @empties = 0
          out.concat(emit(w, a))
          @next_emit = w + 1
        elsif @empties < @max_empty
          @empties += 1
          out.concat(emit(w, Window.new))
          @next_emit = w + 1
        else
          nxt = @high - @late
          @acc.each_key { |k| nxt = k if k >= w && k < nxt }
          @skipped_windows += nxt - w
          @next_emit = nxt
          @streak_start = nil
          @triggered = false
          if @level != -1
            out << { 'kind' => 'level', 'window' => w, 'from' => name(@level), 'to' => 'normal', 'density_micro' => 0 }
            @level = -1
          end
        end
      end
      out
    end

    def emit(w, a)
      @windows += 1
      n = a.agents_over ? [a.hll_agents.estimate, MAX_AGENTS].min : a.agents.size
      possible = n * (n - 1) / 2
      distinct = a.pairs_over ? [a.hll_pairs.estimate, possible].min : a.pairs.size
      density = SmartWatch.density_micro(a.total, possible, @window_ms)
      ratio = possible.positive? ? [MICRO, (distinct.to_f * 1e6 / possible.to_f).floor].min : 0
      entries = a.pairs.map { |k, c| [c, k, true] }
      a.cand.each { |k, c| entries << [c, k, false] unless a.pairs.key?(k) }
      entries.sort! { |x, y| (y[0] <=> x[0]).nonzero? || (x[1] <=> y[1]) }
      top = entries.first(@lim['top_k']).map do |c, k, ex|
        pa, pb = k.split("\n", 2)
        { 'a' => pa, 'b' => pb, 'count' => c, 'exact' => ex }
      end
      before = @level
      @level = grade(density, n)
      nm = name(@level)
      out = [{ 'kind' => 'window', 'window' => w, 'start_ms' => w * @window_ms, 'messages' => a.total,
               'self_messages' => a.self_messages, 'agents' => n, 'pairs' => distinct, 'possible_pairs' => possible,
               'density_micro' => density, 'pair_ratio_micro' => ratio, 'exact' => !(a.pairs_over || a.agents_over),
               'level' => nm, 'top' => top }]
      out << { 'kind' => 'level', 'window' => w, 'from' => name(before), 'to' => nm, 'density_micro' => density } if @level != before
      r = reset_due(w, top, density)
      out << r if r
      out
    end

    def name(i) = i.negative? ? 'normal' : @levels[i][0]

    def grade(density, agents)
      return -1 if agents < @policy['min_agents']

      raw = -1
      @levels.each_with_index { |(_, min), i| raw = i if density >= min }
      return raw if raw >= @level

      h = @policy['hysteresis_permille']
      @level.downto(raw + 1) { |j| return j if density * 1000 >= @levels[j][1] * (1000 - h) }
      raw
    end

    def reset_due(w, top, density)
      r = @reset
      if @level < @reset_idx
        @streak_start = nil
        @triggered = false
        return nil
      end
      @streak_start ||= w
      return nil if r['mode'] == 'off' || @triggered

      sustained = (w - @streak_start + 1) * @window_ms
      return nil if sustained < r['sustain_ms']
      return nil if @last_trigger && (w - @last_trigger) * @window_ms < r['cooldown_ms']

      @triggered = true
      @last_trigger = w
      agents = []
      top.each do |t|
        break if t['count'] < r['hot_pair_min_count']

        [t['a'], t['b']].each { |x| agents << x if !agents.include?(x) && agents.size < r['max_agents'] }
      end
      { 'kind' => 'reset', 'window' => w, 'mode' => r['mode'], 'level' => name(@level), 'density_micro' => density,
        'sustained_ms' => sustained, 'agents' => agents }
    end
  end

  # ---------------------------------------------------------------- audit chain

  # sha256 of the canonical JSON of the record without "hash"; raises CanonicalError when it has none.
  def self.record_hash(record) = sha256_hex(canonical(record.except('hash')))

  # Verify an audit chain: {'ok' => bool, 'index' => Integer or nil, 'message' => String}.
  def self.verify_audit(records)
    prev = GENESIS
    records.each_with_index do |r, i|
      fail_at = ->(m) { { 'ok' => false, 'index' => i, 'message' => "record #{i}: #{m}" } }
      return fail_at.("seq is not #{i}") unless r.is_a?(Hash) && r['seq'].is_a?(Integer) && r['seq'] == i
      return fail_at.("prev does not match the hash of record #{i - 1}") unless r['prev'] == prev

      h = begin
        record_hash(r)
      rescue CanonicalError
        return fail_at.('has no canonical form')
      end
      return fail_at.('hash does not match its content') unless r['hash'] == h

      prev = h
    end
    { 'ok' => true, 'index' => nil, 'message' => "#{records.size} records, chain intact, head #{prev}" }
  end

  # ---------------------------------------------------------------- agent side: HTTP

  # Percent-encode one path segment (RFC 3986 unreserved characters kept; "/" becomes %2F).
  def self.quote_id(s) = s.b.gsub(/[^A-Za-z0-9\-._~]/n) { |c| format('%%%02X', c.ord) }

  # Calls to the Python monitor (Net::HTTP, a new connection per request; Net::HTTP never follows redirects,
  # which would carry the bearer token elsewhere).
  class Client
    # The monitor answered with a status other than 2xx.
    class ClientError < StandardError
      attr_reader :status, :body

      def initialize(status, body, text)
        super("HTTP #{status}: #{text[0, 300]}")
        @status = status
        @body = body
      end
    end

    # The largest answer read; a longer one is an error.
    MAX_RESPONSE_BYTES = 32 * 1024 * 1024
    # Exceptions that mean "the monitor could not be reached": retry later.
    NETWORK_ERRORS = [IOError, SystemCallError, SocketError, Timeout::Error, OpenSSL::SSL::SSLError, Net::HTTPBadResponse,
                      Net::ProtocolError, EOFError].freeze

    attr_reader :url

    def initialize(url, token = nil, timeout: 5.0)
      raise ArgumentError, 'the monitor URL must start with http:// or https://' unless url.start_with?('http://', 'https://')

      @url = url.sub(%r{/+\z}, '')
      @uri = URI(@url)
      @token = token
      @timeout = timeout
    end

    # One request; returns the parsed JSON answer (or the text when it is not a JSON object or array). Raises
    # ClientError for a non-2xx answer and one of NETWORK_ERRORS when the monitor cannot be reached.
    def request(method, path, body = nil)
      full = "#{@uri.path}#{path}"
      req = method == 'POST' ? Net::HTTP::Post.new(full) : Net::HTTP::Get.new(full)
      req['Accept'] = 'application/json'
      req['Authorization'] = "Bearer #{@token}" if @token && !@token.empty?
      if method == 'POST'
        req['Content-Type'] = 'application/json'
        req.body = body.nil? ? '' : SmartWatch.canonical(body)
      end
      code = nil
      text = +''
      Net::HTTP.start(@uri.host, @uri.port, use_ssl: @uri.scheme == 'https', open_timeout: @timeout,
                                            read_timeout: @timeout, write_timeout: @timeout) do |h|
        h.request(req) do |res|
          code = res.code.to_i
          res.read_body do |chunk|
            raise IOError, "the answer is longer than #{MAX_RESPONSE_BYTES} bytes" if text.bytesize + chunk.bytesize > MAX_RESPONSE_BYTES

            text << chunk
          end
        end
      end
      text.force_encoding(Encoding::UTF_8)
      unless code.between?(200, 299)
        parsed = begin
          JSON.parse(text)
        rescue JSON::ParserError
          text
        end
        raise ClientError.new(code, parsed, text)
      end
      return text unless text.start_with?('{', '[')

      begin
        JSON.parse(text)
      rescue JSON::ParserError => e
        raise IOError, "the monitor answered with invalid JSON: #{e.message}"
      end
    end

    # POST /v1/events with {"events": [...]}.
    def events(events) = request('POST', '/v1/events', { 'events' => events })

    # GET /v1/agents/{id}/commands: the pending commands.
    def commands(agent_id)
      r = request('GET', "/v1/agents/#{SmartWatch.quote_id(agent_id)}/commands")
      raise IOError, 'the monitor answered the commands request without a commands list' unless r.is_a?(Hash) && r['commands'].is_a?(Array)

      r['commands']
    end

    # POST /v1/resets/{reset_id}/ack with {"agent_id": id}.
    def ack(reset_id, agent_id = nil)
      request('POST', "/v1/resets/#{SmartWatch.quote_id(reset_id)}/ack", agent_id ? { 'agent_id' => agent_id } : {})
    end
  end

  # Wall-clock milliseconds (event timestamps).
  def self.wall_ms = Process.clock_gettime(Process::CLOCK_REALTIME, :millisecond)

  # The agent-side reporter (spec/PORTING.md item 9). #record adds to an in-memory Hash keyed by
  # (src, dst, ts_ms - ts_ms mod 1000) and never touches the network; a background thread (after #start) sends
  # it every second, plus or minus up to 200 ms of random jitter, as POST /v1/events, at most 10,000 events per
  # request, sorted by time, src, dst. A network failure or a 5xx answer keeps the events for the next send;
  # 400/401/403/413 drops them (counted in #rejected). At most +max_keys+ keys are kept; messages beyond that are
  # counted in #dropped. #close stops the thread and sends what is left.
  class Reporter
    BATCH = 10_000
    REFUSED = [400, 401, 403, 413].freeze

    attr_reader :client

    def initialize(url_or_client, token = nil, interval: 1.0, jitter: 0.2, max_keys: 100_000, bucket_ms: 1000)
      @client = url_or_client.is_a?(Client) ? url_or_client : Client.new(url_or_client, token)
      raise ArgumentError, 'bucket_ms must be from 1 to 60000' unless bucket_ms.between?(1, 60_000)

      @interval = interval
      @jitter = jitter
      @max_keys = max_keys
      @bucket_ms = bucket_ms
      @buf = {}
      @lock = Mutex.new
      @send_lock = Mutex.new
      @stop = Queue.new
      @thread = nil
      @sent = @dropped = @rejected = @errors = 0
    end

    # Messages the monitor accepted / lost to max_keys / refused by the monitor; failed sends.
    def sent = @lock.synchronize { @sent }
    def dropped = @lock.synchronize { @dropped }
    def rejected = @lock.synchronize { @rejected }
    def errors = @lock.synchronize { @errors }

    # +count+ messages from +src+ to +dst+ at +ts_ms+ (now when nil); WatchError for an invalid event.
    def record(src, dst, count = 1, ts_ms: nil)
      ts = ts_ms || SmartWatch.wall_ms
      SmartWatch.check_event(src, dst, ts, count)
      key = [ts - ts % @bucket_ms, src, dst]
      @lock.synchronize { put(key, count) }
    end

    # Send everything recorded so far; returns the messages accepted. Safe to call from any thread.
    def flush
      @send_lock.synchronize do
        buf = @lock.synchronize { b = @buf; @buf = {}; b } # rubocop:disable Style/Semicolon
        items = buf.to_a.sort_by(&:first)   # keys are [ts, src, dst]: time, then src, then dst
        accepted = 0
        (0...items.size).step(BATCH) do |i|
          part = items[i, BATCH]
          evs = part.map { |(t, s, d), c| { 'src' => s, 'dst' => d, 'ts_ms' => t, 'count' => c } }
          sum = part.sum { |_, c| c }
          begin
            res = @client.events(evs)
          rescue Client::ClientError, *Client::NETWORK_ERRORS => e
            if e.is_a?(Client::ClientError) && REFUSED.include?(e.status)
              warn "smartwatch: the monitor refused a batch: #{e.message}"
              @lock.synchronize { @rejected += sum }
              next
            end
            warn "smartwatch: sending to the monitor failed (kept for the next send): #{e.message}"
            @lock.synchronize do
              @errors += 1
              items[i..].each { |k, c| put(k, c) }
            end
            break
          end
          bad = {}
          if res.is_a?(Hash) && res['rejected'].is_a?(Array)
            res['rejected'].each do |r|
              idx = r.is_a?(Hash) ? r['index'] : nil
              bad[idx] = true if idx.is_a?(Integer) && idx >= 0 && idx < evs.size
            end
          end
          n_bad = bad.keys.sum { |j| evs[j]['count'] }
          acc = sum - n_bad
          accepted += acc
          @lock.synchronize do
            @rejected += n_bad
            @sent += acc
          end
        end
        accepted
      end
    end

    # Start the sending thread.
    def start
      @lock.synchronize do
        return self if @thread

        @thread = Thread.new do
          loop do
            wait = @interval + (@jitter.positive? ? rand(-@jitter..@jitter) : 0)
            break if @stop.pop(timeout: [wait, 0].max)

            begin
              flush
            rescue StandardError => e
              warn "smartwatch: reporter flush failed: #{e.class}: #{e.message}"
            end
          end
        end
      end
      self
    end

    # Stop the thread and send what is left.
    def close
      t = @lock.synchronize { th = @thread; @thread = nil; th } # rubocop:disable Style/Semicolon
      if t
        @stop << true
        t.join(5)
      end
      flush
    end

    private

    def put(key, count) # with @lock held
      if @buf.key?(key)
        @buf[key] = [@buf[key] + count, MAX_COUNT].min
      elsif @buf.size < @max_keys
        @buf[key] = count
      else
        @dropped += count
      end
    end
  end

  # Pulls reset commands for one agent (spec/PORTING.md item 10): every +interval+ seconds a GET
  # /v1/agents/{id}/commands; for each {"type": "reset", ...} command the block runs, and when it returns
  # normally the command is acknowledged (POST /v1/resets/{reset_id}/ack). A block that raises: no
  # acknowledgement, the command comes again (the block must tolerate repeats; reset_id tells them apart).
  class CommandPoller
    attr_reader :agent_id

    def initialize(client, agent_id, interval: 1.0, &on_reset)
      raise ArgumentError, 'a block (the reset handler) is required' unless on_reset

      @client = client
      @agent_id = agent_id
      @interval = interval
      @on_reset = on_reset
      @handled = []
      @lock = Mutex.new
      @stop = Queue.new
      @thread = nil
    end

    # The reset_ids handled and acknowledged so far.
    def handled = @lock.synchronize { @handled.dup }

    # One poll; returns the number of commands handled and acknowledged.
    def poll_once
      n = 0
      @client.commands(@agent_id).each do |cmd|
        next unless cmd.is_a?(Hash) && cmd['type'] == 'reset' && cmd['reset_id'].is_a?(String)

        begin
          @on_reset.call(cmd)
        rescue StandardError => e
          warn "smartwatch: on_reset failed for #{cmd['reset_id']}; not acknowledged: #{e.message}"
          next
        end
        @client.ack(cmd['reset_id'], @agent_id)
        @lock.synchronize { @handled << cmd['reset_id'] }
        n += 1
      end
      n
    end

    # Poll in a background thread.
    def start
      @lock.synchronize do
        return self if @thread

        @thread = Thread.new do
          until @stop.pop(timeout: @interval)
            begin
              poll_once
            rescue Client::ClientError, *Client::NETWORK_ERRORS => e
              warn "smartwatch: polling commands failed: #{e.message}"
            end
          end
        end
      end
      self
    end

    def stop
      t = @lock.synchronize { th = @thread; @thread = nil; th } # rubocop:disable Style/Semicolon
      return unless t

      @stop << true
      t.join(5)
    end
  end
end
