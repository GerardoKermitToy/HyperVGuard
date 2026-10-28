use alloc::alloc::{alloc, dealloc};
use core::{alloc::Layout, marker::PhantomData, ptr::NonNull};
use likely_stable::unlikely;

struct Node<T> {
    previous: Option<Handle<T>>,
    next: Option<Handle<T>>,
    value: T,
}

// Handles never escape the policy engine or survive removal of their node.
// A moved node's handle must only be used with its new owning list.
pub(crate) struct Handle<T>(NonNull<Node<T>>);
impl<T> Copy for Handle<T> {}
impl<T> Clone for Handle<T> {
    fn clone(&self) -> Self {
        *self
    }
}

// Fallible, fixed-size allocations: growth never relocates live elements or
// copies an ever-growing array while the driver's policy spin lock is held.
// The kernel uses fallible nonpaged allocation without an aggregate byte quota.
pub(crate) struct List<T> {
    head: Option<Handle<T>>,
    tail: Option<Handle<T>>,
    len: usize,
    #[cfg(test)]
    pub(crate) fail_allocations: bool,
}
impl<T> List<T> {
    pub(crate) const fn new() -> Self {
        Self {
            head: None,
            tail: None,
            len: 0,
            #[cfg(test)]
            fail_allocations: false,
        }
    }
    pub(crate) fn len(&self) -> usize {
        self.len
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub(crate) fn try_push_back(&mut self, value: T) -> Result<Handle<T>, T> {
        #[cfg(test)]
        if self.fail_allocations {
            return Err(value);
        }
        let Some(len) = self.len.checked_add(1) else {
            return Err(value);
        };
        // SAFETY: this is a nonzero layout, freed with the same layout below.
        // The driver supplies fallible, nonpaged GlobalAlloc at DISPATCH_LEVEL.
        let node = unsafe { alloc(Layout::new::<Node<T>>()) }.cast::<Node<T>>();
        if unlikely(node.is_null()) {
            return Err(value);
        }
        // SAFETY: the fallible allocation was checked for null above.
        let node = unsafe { NonNull::new_unchecked(node) };
        let handle = Handle(node);
        unsafe {
            node.as_ptr().write(Node {
                previous: self.tail,
                next: None,
                value,
            });
            if let Some(tail) = self.tail {
                (*tail.0.as_ptr()).next = Some(handle);
            } else {
                self.head = Some(handle);
            }
        }
        self.tail = Some(handle);
        self.len = len;
        Ok(handle)
    }
    pub(crate) fn bytes(&self) -> usize {
        self.len.saturating_mul(core::mem::size_of::<Node<T>>())
    }
    pub(crate) fn front(&self) -> Option<&T> {
        // SAFETY: head is live and owned by this borrowed list.
        self.head.map(|node| unsafe { self.get(node) })
    }
    pub(crate) fn front_mut(&mut self) -> Option<&mut T> {
        // SAFETY: exclusive list access; head is live and owned by this list.
        self.head.map(|node| unsafe { self.get_mut(node) })
    }
    pub(crate) fn pop_front(&mut self) -> Option<T> {
        // SAFETY: head is live and owned by this list.
        self.head.map(|node| unsafe { self.remove(node) })
    }
    pub(crate) fn clear(&mut self) {
        while self.pop_front().is_some() {}
    }
    pub(crate) fn append(&mut self, other: &mut Self) {
        let Some(head) = other.head else { return };
        // SAFETY: the lists exclusively own disjoint nodes. No allocation,
        // relocation or destruction is needed to transfer a complete chain.
        unsafe {
            (*head.0.as_ptr()).previous = self.tail;
            if let Some(tail) = self.tail {
                (*tail.0.as_ptr()).next = Some(head);
            } else {
                self.head = Some(head);
            }
        }
        self.tail = other.tail;
        self.len += other.len;
        other.head = None;
        other.tail = None;
        other.len = 0;
    }
    pub(crate) fn find(&self, mut predicate: impl FnMut(&T) -> bool) -> Option<Handle<T>> {
        let mut next = self.head;
        while let Some(node) = next {
            // SAFETY: these links belong to this borrowed list.
            let entry = unsafe { node.0.as_ref() };
            if predicate(&entry.value) {
                return Some(node);
            }
            next = entry.next;
        }
        None
    }
    /// # Safety
    /// The handle must name a live node in this list. No mutable reference to its
    /// value may exist for the returned reference's lifetime.
    pub(crate) unsafe fn get(&self, handle: Handle<T>) -> &T {
        unsafe { &(*handle.0.as_ptr()).value }
    }
    /// # Safety
    /// The handle must name a live node in this list. No other reference to its
    /// value may exist for the returned reference's lifetime.
    pub(crate) unsafe fn get_mut(&mut self, handle: Handle<T>) -> &mut T {
        unsafe { &mut (*handle.0.as_ptr()).value }
    }
    /// # Safety
    /// The handle must name a live node owned by this list, with no outstanding
    /// references to its value. Every copy of the handle becomes invalid.
    pub(crate) unsafe fn remove(&mut self, handle: Handle<T>) -> T {
        let node = unsafe { handle.0.as_ptr().read() };
        unsafe {
            if let Some(previous) = node.previous {
                (*previous.0.as_ptr()).next = node.next;
            } else {
                self.head = node.next;
            }
            if let Some(next) = node.next {
                (*next.0.as_ptr()).previous = node.previous;
            } else {
                self.tail = node.previous;
            }
            dealloc(handle.0.as_ptr().cast(), Layout::new::<Node<T>>());
        }
        self.len -= 1;
        node.value
    }
    /// # Safety
    /// The handle must name a live node in this list, with no outstanding
    /// references to its value. Ownership transfers without allocation or free.
    #[cfg(test)]
    pub(crate) unsafe fn move_to(&mut self, handle: Handle<T>, other: &mut Self) {
        let node = handle.0.as_ptr();
        unsafe {
            let previous = (*node).previous;
            let next = (*node).next;
            if let Some(previous) = previous {
                (*previous.0.as_ptr()).next = next;
            } else {
                self.head = next;
            }
            if let Some(next) = next {
                (*next.0.as_ptr()).previous = previous;
            } else {
                self.tail = previous;
            }
            (*node).previous = other.tail;
            (*node).next = None;
            if let Some(tail) = other.tail {
                (*tail.0.as_ptr()).next = Some(handle);
            } else {
                other.head = Some(handle);
            }
        }
        self.len -= 1;
        other.tail = Some(handle);
        other.len += 1;
    }
    pub(crate) fn iter(&self) -> Iter<'_, T> {
        Iter {
            next: self.head,
            marker: PhantomData,
        }
    }
    pub(crate) fn iter_mut(&mut self) -> IterMut<'_, T> {
        IterMut {
            next: self.head,
            marker: PhantomData,
        }
    }
}
impl<T> Drop for List<T> {
    fn drop(&mut self) {
        // Iterative destruction also bounds kernel stack use for long lists.
        self.clear();
    }
}
pub(crate) struct Iter<'a, T> {
    next: Option<Handle<T>>,
    marker: PhantomData<&'a T>,
}
impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a T;
    fn next(&mut self) -> Option<Self::Item> {
        // SAFETY: the iterator borrows the whole list, so all links remain live.
        let node = unsafe { self.next?.0.as_ref() };
        self.next = node.next;
        Some(&node.value)
    }
}
pub(crate) struct IterMut<'a, T> {
    next: Option<Handle<T>>,
    marker: PhantomData<&'a mut T>,
}
impl<'a, T> Iterator for IterMut<'a, T> {
    type Item = &'a mut T;
    fn next(&mut self) -> Option<Self::Item> {
        // SAFETY: the iterator exclusively borrows the list and visits each live
        // node exactly once; the links form an acyclic, append/remove-only list.
        let node = unsafe { self.next?.0.as_mut() };
        self.next = node.next;
        Some(&mut node.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{rc::Rc, vec::Vec};
    use core::cell::Cell;

    #[test]
    fn grows_past_old_limits_and_removes_without_moving_other_nodes() {
        let mut list = List::new();
        let handles: Vec<_> = (0..4097).map(|i| list.try_push_back(i).unwrap()).collect();
        for &i in &[0, 2048, 4096] {
            assert_eq!(unsafe { list.remove(handles[i]) }, i);
        }
        for (i, &handle) in handles.iter().enumerate() {
            if ![0, 2048, 4096].contains(&i) {
                assert_eq!(*unsafe { list.get(handle) }, i);
            }
        }
        for value in list.iter_mut() {
            *value += 1;
        }
        assert_eq!(list.len(), 4094);
        assert_eq!(list.pop_front(), Some(2));
        list.clear();
        assert!(list.is_empty());
        assert_eq!(list.try_push_back(7).map(|_| ()), Ok(()));
        assert_eq!(list.pop_front(), Some(7));
    }

    #[test]
    fn moving_nodes_preserves_addresses_and_defers_destruction_without_allocation() {
        struct Value {
            id: usize,
            drops: Rc<Cell<usize>>,
        }
        impl Drop for Value {
            fn drop(&mut self) {
                self.drops.set(self.drops.get() + 1);
            }
        }
        let drops = Rc::new(Cell::new(0));
        let mut source = List::new();
        let mut retired = List::new();
        let handles: Vec<_> = (0..4097)
            .map(|id| {
                source
                    .try_push_back(Value {
                        id,
                        drops: drops.clone(),
                    })
                    .unwrap_or_else(|_| panic!())
            })
            .collect();
        let addresses: Vec<_> = handles
            .iter()
            .map(|&h| unsafe { source.get(h) } as *const Value)
            .collect();
        retired.fail_allocations = true;
        for i in (0..handles.len()).step_by(2) {
            unsafe { source.move_to(handles[i], &mut retired) };
        }
        assert_eq!(source.len(), 2048);
        assert_eq!(retired.len(), 2049);
        assert_eq!(drops.get(), 0);
        for (i, &handle) in handles.iter().enumerate() {
            let owner = if i.is_multiple_of(2) {
                &retired
            } else {
                &source
            };
            let value = unsafe { owner.get(handle) };
            assert_eq!(value.id, i);
            assert_eq!(value as *const Value, addresses[i]);
        }
        assert!(source.iter().map(|v| v.id).eq((1..4097).step_by(2)));
        assert!(retired.iter().map(|v| v.id).eq((0..4097).step_by(2)));
        source.clear();
        assert_eq!(drops.get(), 2048);
        retired.clear();
        assert_eq!(drops.get(), 4097);
    }

    #[test]
    fn allocation_failure_keeps_values_and_destruction_is_exactly_once() {
        struct Value(Rc<Cell<usize>>);
        impl Drop for Value {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let drops = Rc::new(Cell::new(0));
        let mut list = List::new();
        assert!(list.try_push_back(Value(drops.clone())).is_ok());
        list.fail_allocations = true;
        let value = match list.try_push_back(Value(drops.clone())) {
            Err(value) => value,
            Ok(_) => panic!("expected allocation failure"),
        };
        assert_eq!(list.len(), 1);
        assert_eq!(drops.get(), 0);
        drop(value);
        drop(list);
        assert_eq!(drops.get(), 2);
    }
}
