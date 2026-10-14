'use strict';

class WatchError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}
class PolicyError extends WatchError {
  constructor(message) { super('WATCH-BAD-POLICY', message); }
}
class EventError extends WatchError {
  constructor(message) { super('WATCH-BAD-EVENT', message); }
}

module.exports = { WatchError, PolicyError, EventError };
