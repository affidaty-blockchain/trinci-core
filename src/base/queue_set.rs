// This file is part of TRINCI.
//
// Copyright (C) 2021 Affidaty Spa.
//
// TRINCI is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// TRINCI is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
// for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with TRINCI. If not, see <https://www.gnu.org/licenses/>.

//! First In First Out queue that prevents duplicates insertion.

use std::collections::vec_deque::Iter;
use std::collections::{HashSet, VecDeque};

/// Queue Set structure.
#[derive(Debug)]
pub struct QueueSet<T> {
    /// HashSet for quick presence check.
    set: HashSet<T>,
    /// Unconfirmed transactions queue sorted by arrival time.
    fifo: VecDeque<T>,
}

impl<T> Default for QueueSet<T> {
    fn default() -> Self {
        Self {
            set: HashSet::default(),
            fifo: VecDeque::default(),
        }
    }
}

impl<T> QueueSet<T>
where
    T: std::cmp::Eq + std::hash::Hash + Clone,
{
    /// Instance a new empty QueueSet structure.
    ///
    /// # Example
    ///
    /// ```
    /// # use trinci_core::base::queue_set::QueueSet;
    /// let queue: QueueSet<i32> = QueueSet::new();
    /// ```
    pub fn new() -> Self {
        QueueSet::default()
    }

    /// Get the number of entries in the queue.
    ///
    /// # Example
    ///
    /// ```
    /// # use trinci_core::base::queue_set::QueueSet;
    /// let queue: QueueSet<i32> = QueueSet::new();
    /// assert_eq!(queue.len(), 0);
    /// ```
    pub fn len(&self) -> usize {
        self.fifo.len()
    }

    /// Checks if the queue is empty.
    ///
    /// # Example
    ///
    /// ```
    /// # use trinci_core::base::queue_set::QueueSet;
    /// let mut queue: QueueSet<i32> = QueueSet::new();
    /// assert!(queue.is_empty());
    /// queue.push(1);
    /// assert!(!queue.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Checks if the queue contains the given key.
    ///
    /// # Example
    ///
    /// ```
    /// # use trinci_core::base::queue_set::QueueSet;
    /// let mut queue = QueueSet::new();
    /// queue.push(1);
    /// assert!(queue.contains(&1));
    /// assert!(!queue.contains(&3));
    /// ```
    pub fn contains(&self, val: &T) -> bool {
        self.set.contains(val)
    }

    /// Adds the given key/value pair to the queue.
    ///
    /// If the key is already present returns false and the previous value is retained.
    ///
    /// # Example
    ///
    /// ```
    /// # use trinci_core::base::queue_set::QueueSet;
    /// let mut queue = QueueSet::new();
    /// assert!(queue.push(1));
    /// assert!(!queue.push(1));
    /// ```
    pub fn push(&mut self, val: T) -> bool {
        if self.set.insert(val.clone()) {
            self.fifo.push_back(val);
            true
        } else {
            false
        }
    }

    /// Removes and returns the least recently inserted key/value pair from the queue.
    ///
    /// # Example
    ///
    /// ```
    /// # use trinci_core::base::queue_set::QueueSet;
    /// let mut queue = QueueSet::new();
    /// queue.push(1);
    /// queue.push(2);
    /// assert_eq!(queue.pop(), Some(1));
    /// assert_eq!(queue.pop(), Some(2));
    /// assert_eq!(queue.pop(), None);
    /// ```
    pub fn pop(&mut self) -> Option<T> {
        self.fifo.pop_front().map(|val| {
            self.set.remove(&val);
            val
        })
    }

    /// Remove an element by key.
    ///
    /// # Example
    ///
    /// ```
    /// # use trinci_core::base::queue_set::QueueSet;
    /// let mut queue = QueueSet::new();
    /// queue.push(1);
    /// queue.push(2);
    /// assert_eq!(queue.remove(&2), true);
    /// assert_eq!(queue.remove(&3), false);
    /// ```
    pub fn remove(&mut self, val: &T) -> bool {
        let res = self.set.remove(val);
        if res {
            for (i, v) in self.fifo.iter().enumerate() {
                if v.eq(val) {
                    self.fifo.remove(i);
                    break;
                }
            }
        }
        res
    }

    /// Get an immutable iterator over the queue elements.
    pub fn iter(&self) -> Iter<T> {
        self.fifo.iter()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn push() {
        let mut queue = QueueSet::new();

        queue.push(1);
        queue.push(2);

        assert_eq!(queue.len(), 2);
        assert!(!queue.is_empty());
    }

    #[test]
    fn push_duplicate() {
        let mut queue = QueueSet::new();
        queue.push(1);

        let ret = queue.push(1);

        assert!(!ret);
    }

    #[test]
    fn pop() {
        let mut queue = QueueSet::new();
        queue.push(1);
        queue.push(2);

        let val = queue.pop();

        assert_eq!(queue.len(), 1);
        assert_eq!(Some(1), val);
    }

    #[test]
    fn iterator() {
        let mut queue = QueueSet::new();
        queue.push(1);
        queue.push(2);
        queue.push(3);

        let mut iter = queue.iter();

        assert_eq!(iter.next(), Some(&1));
        assert_eq!(iter.next_back(), Some(&3));
    }
}
