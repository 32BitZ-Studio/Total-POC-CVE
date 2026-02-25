use core::{
    arch::asm,
    cell::{LazyCell, RefCell, UnsafeCell},
    mem::size_of,
    ptr::NonNull,
    sync::atomic::{AtomicU64, Ordering},
};

use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit, Nonce, Tag};
use bit_field::BitField;
use bytemuck::{bytes_of, checked::pod_read_unaligned, offset_of, NoUninit, Pod, Zeroable};
use snp_types::{
    ghcb::{
        msr_protocol::{GhcbInfo, GhcbProtocolMsr, TerminateReasonCode},
        Ghcb, ProtocolVersion,
    },
    guest_message::{Algo, Content, ContentV1, Message},
    intercept::VMEXIT_IOIO,
    secrets::Secrets,
    Reserved,
};
use volatile::{map_field, VolatilePtr};
use x86_64::structures::paging::PhysFrame;

use crate::{pa_of, FakeSync};

#[no_mangle]
#[link_section = ".secrets"]
static SECRETS_PAGE: FakeSync<UnsafeCell<[u8; 0x1000]>> =
    FakeSync::new(UnsafeCell::new([0; 0x1000]));

static SECRETS: FakeSync<LazyCell<Secrets>> = FakeSync::new(LazyCell::new(|| {
    let mut bytes = [0; 0x1000];
    unsafe {
        core::intrinsics::volatile_copy_nonoverlapping_memory(&mut bytes, SECRETS_PAGE.get(), 1);
    }
    pod_read_unaligned(&bytes)
}));

/// Initialize a GHCB and pass it to the closure.
pub fn with_ghcb<R>(f: impl FnOnce(&mut VolatilePtr<'static, Ghcb>) -> R) -> Result<R, GhcbInUse> {
    static GHCB: FakeSync<LazyCell<RefCell<VolatilePtr<'static, Ghcb>>>> =
        FakeSync::new(LazyCell::new(|| {
            #[link_section = ".shared"]
            static GHCB_STORAGE: FakeSync<UnsafeCell<Ghcb>> =
                FakeSync::new(UnsafeCell::new(Ghcb::ZERO));

            let address = pa_of!(GHCB_STORAGE);
            let address = PhysFrame::from_start_address(address).unwrap();

            register_ghcb(address);

            let mut msr = GhcbProtocolMsr::MSR;
            unsafe {
                msr.write(u64::from(GhcbInfo::GhcbGuestPhysicalAddress { address }));
            }

            RefCell::new(unsafe { VolatilePtr::new(NonNull::from(&GHCB_STORAGE).cast()) })
        }));

    let res = GHCB.try_borrow_mut();
    let mut ghcb = res.map_err(|_| GhcbInUse(()))?;
    Ok(f(&mut ghcb))
}

#[derive(Debug)]
pub struct GhcbInUse(());

fn register_ghcb(request_address: PhysFrame) {
    let mut msr = GhcbProtocolMsr::MSR;

    // Write the request.
    let request = u64::from(GhcbInfo::RegisterGhcbGpaRequest {
        address: request_address,
    });
    unsafe { msr.write(request) }

    // Execute the request.
    vmgexit();

    // Read the response.
    let response = GhcbInfo::try_from(unsafe { msr.read() }).unwrap();

    // Verify the response.
    let GhcbInfo::RegisterGhcbGpaResponse {
        address: response_address,
    } = response
    else {
        panic!("unexpected response: {response:?}")
    };
    assert_eq!(Some(request_address), response_address);
}

fn vmgexit() {
    // LLVM doesn't support the `vmgexit` instruction
    unsafe { asm!("rep vmmcall", options(nostack, preserves_flags)) }
}

/// A macro to write to a field of the GHCB and also mark it in the valid
/// bitmap.
macro_rules! ghcb_write {
    ($ghcb:ident.$field:ident = $value:expr) => {{
        map_field!($ghcb.$field).write($value);
        let bit_offset = offset_of!(Ghcb::ZERO, Ghcb, $field);
        map_field!($ghcb.valid_bitmap).update(|mut value| {
            value.set_bit(bit_offset / 8, true);
            value
        });
    }};
}

pub fn ioio_write(port: u16, value: u32) {
    with_ghcb(|ghcb| {
        ghcb.write(Ghcb::ZERO);
        map_field!(ghcb.protocol_version).write(ProtocolVersion::VERSION2);

        let mut sw_exit_info1 = 0;
        sw_exit_info1.set_bit(0, false); // OUT instruction
        sw_exit_info1.set_bit(6, true); // 32-bit operand size
        sw_exit_info1.set_bits(16..=31, u64::from(port));

        ghcb_write!(ghcb.sw_exit_code = VMEXIT_IOIO);
        ghcb_write!(ghcb.sw_exit_info1 = sw_exit_info1);
        ghcb_write!(ghcb.sw_exit_info2 = 0);
        ghcb_write!(ghcb.rax = u64::from(value));

        vmgexit();
    })
    .unwrap();
}

pub trait GuestRequest: NoUninit {
    const MSG_TYPE: u8;
    const MSG_VERSION: u8;
}

const N: usize = 0x590;

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct MsgCpuid {
    pub count: u32,
    pub _reserved1: Reserved<4>,
    pub _reserved2: Reserved<8>,
    pub functions: [CpuidFunction; 64],
    pub padding: Reserved<N>,
}

impl core::fmt::Debug for MsgCpuid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MsgCpuid")
            .field("padding", &self.padding)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct CpuidFunction {
    pub eax_in: u32,
    pub ecx_in: u32,
    pub xcr0_in: u32,
    pub xss_in: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub _reserved: Reserved<8>,
}

impl GuestRequest for MsgCpuid {
    const MSG_TYPE: u8 = 1;
    const MSG_VERSION: u8 = 1;
}

pub fn build_request_message<T>(request: T) -> (u64, Message)
where
    T: GuestRequest,
{
    static MSG_SEQNO: AtomicU64 = AtomicU64::new(1);
    let msg_seqno = MSG_SEQNO.fetch_add(2, Ordering::SeqCst);

    let mut iv = [0; 12];
    iv[0..8].copy_from_slice(&msg_seqno.to_ne_bytes());
    let nonce = Nonce::from(iv);

    let msg_size = u16::try_from(size_of::<T>()).unwrap();

    let mut message = Message::new(
        [0; 0x20],
        msg_seqno,
        Algo::Aes256Gcm,
        Content::V1(ContentV1::new(
            0x60,
            T::MSG_TYPE,
            T::MSG_VERSION,
            msg_size,
            0,
            [0; 4000],
        )),
    );

    let associated_data = &bytes_of(&message)[0x30..=0x5f];
    let associated_data: [u8; 48] = pod_read_unaligned(associated_data);

    let Content::V1(content) = &mut message.content;
    let payload = &mut content.payload[..size_of::<T>()];
    payload.copy_from_slice(bytes_of(&request));

    let Secrets::V3(secrets) = &**SECRETS;
    let cipher = Aes256Gcm::new_from_slice(&secrets.vmpck0).unwrap();
    let tag = cipher
        .encrypt_in_place_detached(&nonce, &associated_data, payload)
        .unwrap();

    let tag = <[u8; 16]>::from(tag);
    message.auth_tag[..16].copy_from_slice(&tag);

    (msg_seqno, message)
}

pub fn extract_response(msg_seqno: u64, message: &mut Message) -> (u8, u8, &[u8]) {
    assert_eq!(message.msg_seqno, msg_seqno);

    let mut iv = [0; 12];
    iv[0..8].copy_from_slice(&msg_seqno.to_ne_bytes());
    let nonce = Nonce::from(iv);

    let auth_tag = Tag::from_slice(&message.auth_tag[..16]);

    let associated_data = &bytes_of(message)[0x30..=0x5f];
    let associated_data: [u8; 48] = pod_read_unaligned(associated_data);

    let Algo::Aes256Gcm = message.algo;

    let Content::V1(content) = &mut message.content;
    assert_eq!(content.msg_vmpck, 0);
    assert_eq!({ content.hdr_size }, 0x60);

    let msg_size = usize::try_from(content.msg_size).unwrap();
    let payload = &mut content.payload[..msg_size];

    let Secrets::V3(secrets) = &**SECRETS;
    let cipher = Aes256Gcm::new_from_slice(&secrets.vmpck0).unwrap();
    cipher
        .decrypt_in_place_detached(&nonce, &associated_data, payload, auth_tag)
        .unwrap();

    (content.msg_type, content.msg_version, payload)
}

pub fn do_guest_request(request: Message) -> Message {
    #[link_section = ".shared"]
    static REQ: FakeSync<UnsafeCell<[u8; 0x1000]>> = FakeSync::new(UnsafeCell::new([0; 0x1000]));
    #[link_section = ".shared"]
    static RSP: FakeSync<UnsafeCell<[u8; 0x1000]>> = FakeSync::new(UnsafeCell::new([0; 0x1000]));

    unsafe {
        core::intrinsics::volatile_copy_nonoverlapping_memory(REQ.get().cast(), &request, 1);
    }

    let req_pa = pa_of!(REQ);
    let rsp_pa = pa_of!(RSP);

    let sw_exit_info2 = with_ghcb(|ghcb| {
        ghcb.write(Ghcb::ZERO);
        map_field!(ghcb.protocol_version).write(ProtocolVersion::VERSION2);

        ghcb_write!(ghcb.sw_exit_code = 0x8000_0011);
        ghcb_write!(ghcb.sw_exit_info1 = req_pa.as_u64());
        ghcb_write!(ghcb.sw_exit_info2 = rsp_pa.as_u64());

        vmgexit();

        map_field!(ghcb.sw_exit_info2).read()
    })
    .unwrap();
    assert_eq!(sw_exit_info2, 0);

    let mut bytes = [0; 0x1000];
    unsafe {
        core::intrinsics::volatile_copy_nonoverlapping_memory(&mut bytes, RSP.get().cast(), 1);
    }
    bytemuck::checked::pod_read_unaligned(&bytes)
}

pub fn exit() -> ! {
    let mut msr = GhcbProtocolMsr::MSR;

    loop {
        // Write the request.
        let request = u64::from(GhcbInfo::TerminationRequest {
            reason_code: TerminateReasonCode::GENERAL_TERMINATION_REQUEST,
        });
        unsafe {
            msr.write(request);
        }

        vmgexit();
    }
}
