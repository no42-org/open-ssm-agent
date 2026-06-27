/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Reliable-stream ordering and dedup (AD-8).
//!
//! Transport-agnostic: a transport adapter (MQTT today) feeds the cleartext
//! `seq` of each received envelope here; this layer orders them, drops
//! duplicates and replays, buffers out-of-order arrivals up to a bound, and
//! reports the cumulative ack. The payload `T` is **opaque** — only the sequence
//! number is inspected — so ordering is independent of the (encrypted) payload
//! and of the transport's own delivery guarantees (e.g. MQTT QoS).
//!
//! One [`ReorderBuffer`] tracks a single monotonic stream (per `sid`/direction in
//! the [`Envelope`](osa_proto::v1::Envelope) scheme); a higher layer keys one per
//! active stream.

use std::collections::BTreeMap;

/// Outcome of offering one sequenced item to a [`ReorderBuffer`].
#[derive(Debug, PartialEq, Eq)]
pub enum Accept<T> {
    /// Ready to consume in order: the offered item followed by any buffered
    /// items that became contiguous behind it.
    Deliver(Vec<T>),
    /// A duplicate or already-superseded sequence; dropped.
    Duplicate,
    /// Held out of order, awaiting an earlier sequence.
    Buffered,
    /// The out-of-order buffer is full while a gap persists: the missing
    /// sequence is unrecoverable from buffering alone. The rejected item is
    /// returned so the caller can NACK / reset the stream rather than wait
    /// forever.
    Overflow(T),
}

/// Orders a single monotonic `seq` stream — dropping duplicates and buffering
/// out-of-order arrivals within a sliding window of `capacity` sequences ahead of
/// the contiguous head.
///
/// `capacity` bounds the **count** of pending items, not their byte size; with a
/// large `T` the worst-case memory is `capacity × payload`. A `capacity` of `0`
/// disables reordering entirely — only strictly in-order sequences are accepted.
pub struct ReorderBuffer<T> {
    start: u64,
    next: u64,
    pending: BTreeMap<u64, T>,
    capacity: usize,
}

impl<T> ReorderBuffer<T> {
    /// A buffer expecting `start` as the first sequence and buffering at most
    /// `capacity` sequences ahead of the contiguous head before signalling
    /// [`Accept::Overflow`].
    pub fn new(start: u64, capacity: usize) -> Self {
        Self {
            start,
            next: start,
            pending: BTreeMap::new(),
            capacity,
        }
    }

    /// The next sequence still needed; everything below it has been delivered.
    pub fn next_expected(&self) -> u64 {
        self.next
    }

    /// The highest contiguous sequence delivered so far (the cumulative ack), or
    /// `None` if nothing has been delivered yet.
    pub fn ack(&self) -> Option<u64> {
        (self.next > self.start).then(|| self.next - 1)
    }

    /// Number of out-of-order items currently buffered.
    pub fn buffered(&self) -> usize {
        self.pending.len()
    }

    /// Discard all buffered items and resume expecting `start` — the recovery
    /// path after [`Accept::Overflow`] or a stream reset.
    pub fn reset(&mut self, start: u64) {
        self.start = start;
        self.next = start;
        self.pending.clear();
    }

    /// Offer the item carried by sequence `seq`.
    pub fn accept(&mut self, seq: u64, item: T) -> Accept<T> {
        if seq < self.next || self.pending.contains_key(&seq) {
            return Accept::Duplicate;
        }
        if seq == self.next {
            // Deliver it, then drain the now-contiguous run.
            let mut out = vec![item];
            self.next = self.next.saturating_add(1);
            while let Some(next_item) = self.pending.remove(&self.next) {
                out.push(next_item);
                self.next = self.next.saturating_add(1);
            }
            return Accept::Deliver(out);
        }
        // seq > next: only buffer within the sliding window (next, next+capacity].
        // Anything further ahead can never become contiguous from buffering, so
        // it is rejected rather than parked (bounds memory and blocks far-future
        // seq flooding from an untrusted peer).
        if seq.saturating_sub(self.next) > self.capacity as u64 {
            return Accept::Overflow(item);
        }
        self.pending.insert(seq, item);
        Accept::Buffered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buf() -> ReorderBuffer<u64> {
        ReorderBuffer::new(0, 8)
    }

    #[test]
    fn in_order_delivers_each() {
        let mut b = buf();
        assert_eq!(b.accept(0, 0), Accept::Deliver(vec![0]));
        assert_eq!(b.accept(1, 1), Accept::Deliver(vec![1]));
        assert_eq!(b.next_expected(), 2);
    }

    #[test]
    fn out_of_order_is_buffered_then_released_in_order() {
        let mut b = buf();
        assert_eq!(b.accept(2, 2), Accept::Buffered);
        assert_eq!(b.accept(1, 1), Accept::Buffered);
        assert_eq!(b.buffered(), 2);
        // The gap fills: everything contiguous is released at once.
        assert_eq!(b.accept(0, 0), Accept::Deliver(vec![0, 1, 2]));
        assert_eq!(b.next_expected(), 3);
        assert_eq!(b.buffered(), 0);
    }

    #[test]
    fn duplicates_are_dropped() {
        let mut b = buf();
        assert_eq!(b.accept(0, 0), Accept::Deliver(vec![0]));
        assert_eq!(b.accept(0, 0), Accept::Duplicate); // already delivered
        assert_eq!(b.accept(2, 2), Accept::Buffered);
        assert_eq!(b.accept(2, 2), Accept::Duplicate); // already buffered
    }

    #[test]
    fn redelivery_after_ack_is_a_duplicate() {
        let mut b = buf();
        b.accept(0, 0);
        b.accept(1, 1);
        // MQTT redelivers an old seq: dropped, not re-delivered.
        assert_eq!(b.accept(1, 1), Accept::Duplicate);
        assert_eq!(b.next_expected(), 2);
    }

    #[test]
    fn full_buffer_with_a_persistent_gap_overflows() {
        let mut b = ReorderBuffer::new(0, 2);
        assert_eq!(b.accept(1, 1), Accept::Buffered);
        assert_eq!(b.accept(2, 2), Accept::Buffered);
        // seq 0 never arrives and the buffer is full → unrecoverable gap.
        assert_eq!(b.accept(3, 3), Accept::Overflow(3));
        // The contiguous head is still 0 (nothing delivered).
        assert_eq!(b.next_expected(), 0);
    }

    #[test]
    fn honours_a_nonzero_start() {
        let mut b = ReorderBuffer::new(5, 8);
        assert_eq!(b.accept(4, 4), Accept::Duplicate); // before the start
        assert_eq!(b.accept(5, 5), Accept::Deliver(vec![5]));
    }

    #[test]
    fn payload_is_opaque() {
        // The buffer never inspects the payload — here an opaque "ciphertext".
        let mut b: ReorderBuffer<Vec<u8>> = ReorderBuffer::new(0, 8);
        assert_eq!(
            b.accept(0, vec![0xde, 0xad]),
            Accept::Deliver(vec![vec![0xde, 0xad]])
        );
    }

    #[test]
    fn far_future_seq_is_rejected_not_parked() {
        // An untrusted peer injecting a far-future seq cannot poison the buffer.
        let mut b = ReorderBuffer::new(0, 4);
        assert_eq!(b.accept(1_000_000, 1_000_000), Accept::Overflow(1_000_000));
        assert_eq!(b.buffered(), 0);
        // The legitimate head still delivers.
        assert_eq!(b.accept(0, 0), Accept::Deliver(vec![0]));
    }

    #[test]
    fn capacity_zero_is_strict_in_order() {
        let mut b = ReorderBuffer::new(0, 0);
        assert_eq!(b.accept(0, 0), Accept::Deliver(vec![0]));
        assert_eq!(b.accept(2, 2), Accept::Overflow(2)); // any gap overflows
        assert_eq!(b.accept(1, 1), Accept::Deliver(vec![1])); // in order still works
    }

    #[test]
    fn capacity_one_buffers_exactly_one_ahead() {
        let mut b = ReorderBuffer::new(0, 1);
        assert_eq!(b.accept(1, 1), Accept::Buffered);
        assert_eq!(b.accept(2, 2), Accept::Overflow(2)); // 2 is outside the window
        assert_eq!(b.accept(0, 0), Accept::Deliver(vec![0, 1]));
    }

    #[test]
    fn ack_is_none_before_first_delivery() {
        let mut b = ReorderBuffer::new(5, 4);
        assert_eq!(b.ack(), None);
        b.accept(6, 6); // buffered, not yet delivered (gap at 5)
        assert_eq!(b.ack(), None);
        assert_eq!(b.accept(5, 5), Accept::Deliver(vec![5, 6]));
        assert_eq!(b.ack(), Some(6));
    }

    #[test]
    fn max_seq_does_not_panic() {
        let mut b = ReorderBuffer::new(u64::MAX, 4);
        assert_eq!(b.accept(u64::MAX, 0), Accept::Deliver(vec![0]));
    }

    #[test]
    fn reset_recovers_the_stream() {
        let mut b = ReorderBuffer::new(0, 2);
        b.accept(1, 1);
        b.accept(2, 2);
        assert_eq!(b.accept(9, 9), Accept::Overflow(9));
        // Reset and resume from a new start; old buffered items are discarded.
        b.reset(10);
        assert_eq!(b.buffered(), 0);
        assert_eq!(b.accept(10, 10), Accept::Deliver(vec![10]));
        assert_eq!(b.ack(), Some(10));
    }
}
