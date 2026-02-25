#![no_std]

use core::fmt;

use bitflags::bitflags;
use bytemuck::{NoUninit, Pod, Zeroable};

pub mod cpuid;
pub mod ghcb;
pub mod guest_message;
pub mod guest_policy;
pub mod intercept;
pub mod secrets;

/// A type that transparently wraps another type, but replaces the Debug
/// representation with an emtpy one. The Debug representation for reserved
/// values is not of interest.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(transparent)]
pub struct Reserved<const SIZE: usize>([u8; SIZE]);

impl<const SIZE: usize> Reserved<SIZE> {
    pub const ZERO: Self = Self([0; SIZE]);
}

impl<const SIZE: usize> fmt::Debug for Reserved<SIZE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == [0; SIZE] {
            f.debug_struct("Reserved").finish_non_exhaustive()
        } else {
            f.debug_struct("Reserved")
                .field("bytes", &self.0)
                .finish_non_exhaustive()
        }
    }
}

/// A type that transparently wraps another type, but replaces the Debug
/// representation with an emtpy one. The Debug representation for uninteresting
/// values is not of interest.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(transparent)]
pub struct Uninteresting<T>(T);

impl<T> Uninteresting<T> {
    pub const fn new(value: T) -> Self {
        Self(value)
    }
}

impl<T: fmt::Debug> fmt::Debug for Uninteresting<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Uninteresting").finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageType {
    Normal = 0x1,
    Vmsa = 0x2,
    Zero = 0x3,
    Unmeasured = 0x4,
    Secrets = 0x5,
    Cpuid = 0x6,
}

bitflags! {
    #[derive(NoUninit)]
    #[repr(transparent)]
    pub struct VmplPermissions: u8 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const EXECUTE_USER = 1 << 2;
        const EXECUTE_SUPERVISOR = 1 << 3;
        const SUPERVISOR_SHADOW_STACK = 1 << 4;
    }
}
