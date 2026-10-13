//! Resource-bounded adapter for the candidate's Postcard proof codec.
//!
//! A byte cap alone does not prevent a forged vector length from reserving a
//! large allocation before reading its contents. Every nested sequence here
//! loses that untrusted allocation hint and shares an element/depth budget.

use serde::de::{self, DeserializeSeed, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::cell::Cell;
use std::fmt;

const MAX_SEQUENCE: usize = 16_384;
const MAX_DEPTH: usize = 32;

pub(super) fn from_bytes<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, postcard::Error> {
    let budget = Cell::new(bytes.len().saturating_mul(2).saturating_add(64));
    let mut decoder = postcard::Deserializer::from_bytes(bytes);
    let value = T::deserialize(Guard {
        inner: &mut decoder,
        budget: &budget,
        depth: 0,
    })?;
    if !decoder.finalize()?.is_empty() {
        return Err(postcard::Error::DeserializeBadEncoding);
    }
    Ok(value)
}

struct Guard<'a, D> {
    inner: D,
    budget: &'a Cell<usize>,
    depth: usize,
}
struct Visit<'a, V> {
    inner: V,
    budget: &'a Cell<usize>,
    depth: usize,
}
struct Sequence<'a, A> {
    inner: A,
    budget: &'a Cell<usize>,
    depth: usize,
    elements: usize,
}
struct Seed<'a, S> {
    inner: S,
    budget: &'a Cell<usize>,
    depth: usize,
}

macro_rules! delegate {
    ($($name:ident $(($($arg:ident : $ty:ty),* ))?);* $(;)?) => {$ (
        fn $name<V: Visitor<'de>>(self, $($($arg: $ty,)*)? visitor: V) -> Result<V::Value, Self::Error> {
            if self.depth > MAX_DEPTH { return Err(de::Error::custom("proof nesting limit")); }
            self.inner.$name($($($arg,)*)? Visit { inner: visitor, budget: self.budget, depth: self.depth })
        }
    )*};
}

impl<'de, D: Deserializer<'de>> Deserializer<'de> for Guard<'_, D> {
    type Error = D::Error;
    delegate! {
        deserialize_any; deserialize_bool; deserialize_i8; deserialize_i16;
        deserialize_i32; deserialize_i64; deserialize_i128;
        deserialize_u8; deserialize_u16; deserialize_u32; deserialize_u64; deserialize_u128;
        deserialize_f32; deserialize_f64; deserialize_char; deserialize_str; deserialize_string;
        deserialize_bytes; deserialize_byte_buf; deserialize_option; deserialize_unit;
        deserialize_unit_struct(name: &'static str);
        deserialize_newtype_struct(name: &'static str);
        deserialize_seq; deserialize_tuple(len: usize);
        deserialize_tuple_struct(name: &'static str, len: usize);
        deserialize_map;
        deserialize_struct(name: &'static str, fields: &'static [&'static str]);
        deserialize_enum(name: &'static str, variants: &'static [&'static str]);
        deserialize_identifier; deserialize_ignored_any
    }
    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }
}

macro_rules! primitive {
    ($($name:ident($ty:ty));* $(;)?) => {$ (
        fn $name<E: de::Error>(self, value: $ty) -> Result<Self::Value, E> {
            self.inner.$name(value)
        }
    )*};
}

impl<'de, V: Visitor<'de>> Visitor<'de> for Visit<'_, V> {
    type Value = V::Value;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.expecting(formatter)
    }
    primitive! {
        visit_bool(bool); visit_i8(i8); visit_i16(i16); visit_i32(i32); visit_i64(i64); visit_i128(i128);
        visit_u8(u8); visit_u16(u16); visit_u32(u32); visit_u64(u64); visit_u128(u128);
        visit_f32(f32); visit_f64(f64); visit_char(char);
        visit_str(&str); visit_borrowed_str(&'de str); visit_string(String);
        visit_bytes(&[u8]); visit_borrowed_bytes(&'de [u8]); visit_byte_buf(Vec<u8>)
    }
    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_none()
    }
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_unit()
    }
    fn visit_some<D: Deserializer<'de>>(self, inner: D) -> Result<Self::Value, D::Error> {
        self.inner.visit_some(Guard {
            inner,
            budget: self.budget,
            depth: self.depth + 1,
        })
    }
    fn visit_newtype_struct<D: Deserializer<'de>>(self, inner: D) -> Result<Self::Value, D::Error> {
        self.inner.visit_newtype_struct(Guard {
            inner,
            budget: self.budget,
            depth: self.depth + 1,
        })
    }
    fn visit_seq<A: SeqAccess<'de>>(self, inner: A) -> Result<Self::Value, A::Error> {
        if inner
            .size_hint()
            .is_some_and(|length| length > MAX_SEQUENCE)
        {
            return Err(de::Error::custom("proof sequence limit"));
        }
        self.inner.visit_seq(Sequence {
            inner,
            budget: self.budget,
            depth: self.depth + 1,
            elements: 0,
        })
    }
}

impl<'de, A: SeqAccess<'de>> SeqAccess<'de> for Sequence<'_, A> {
    type Error = A::Error;
    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Self::Error> {
        let remaining = self.budget.get();
        if remaining == 0 {
            return Err(de::Error::custom("proof element budget"));
        }
        self.budget.set(remaining - 1);
        let value = self.inner.next_element_seed(Seed {
            inner: seed,
            budget: self.budget,
            depth: self.depth,
        })?;
        if value.is_some() {
            if self.elements >= MAX_SEQUENCE {
                return Err(de::Error::custom("proof sequence limit"));
            }
            self.elements += 1;
        }
        Ok(value)
    }
    // Vec must grow only as actual elements arrive, never from wire length.
    fn size_hint(&self) -> Option<usize> {
        None
    }
}
impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for Seed<'_, S> {
    type Value = S::Value;
    fn deserialize<D: Deserializer<'de>>(self, inner: D) -> Result<Self::Value, D::Error> {
        self.inner.deserialize(Guard {
            inner,
            budget: self.budget,
            depth: self.depth,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn huge_nested_sequence_lengths_fail_before_allocation() {
        let huge = postcard::to_allocvec(&usize::MAX).unwrap();
        assert!(from_bytes::<Vec<u64>>(&huge).is_err());
        let mut nested = vec![1];
        nested.extend(huge);
        assert!(from_bytes::<Vec<Vec<u64>>>(&nested).is_err());
        assert!(
            from_bytes::<Vec<u64>>(&[0, 1]).is_err(),
            "no trailing bytes"
        );
        let original = vec![vec![1u64, 2], vec![3, 4]];
        assert_eq!(
            from_bytes::<Vec<Vec<u64>>>(&postcard::to_allocvec(&original).unwrap()).unwrap(),
            original
        );
    }
    #[test]
    fn absent_postcard_length_hint_does_not_bypass_sequence_limit() {
        // Postcard deliberately withholds the allocation hint when the wire
        // length exceeds remaining bytes. Empty children still consume only
        // one byte each, so the guard must count actual elements as well.
        let mut hostile = postcard::to_allocvec(&(MAX_SEQUENCE + 2)).unwrap();
        hostile.resize(hostile.len() + MAX_SEQUENCE + 1, 0);
        assert_eq!(
            from_bytes::<Vec<Vec<u64>>>(&hostile).unwrap_err(),
            postcard::Error::SerdeDeCustom,
            "sequence cap fires before the missing final element"
        );
        let exact = vec![Vec::<u64>::new(); MAX_SEQUENCE];
        assert_eq!(
            from_bytes::<Vec<Vec<u64>>>(&postcard::to_allocvec(&exact).unwrap()).unwrap(),
            exact
        );
    }
}
