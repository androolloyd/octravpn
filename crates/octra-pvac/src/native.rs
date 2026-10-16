//! Owns every pointer and buffer crossing the C ABI. Handles never escape Rust.
use std::{
    ffi::{c_char, c_void, CStr},
    ptr::NonNull,
};

use crate::{Error, Math};

extern "C" {
    fn octra_pvac_error() -> i32;
    fn octra_pvac_error_message() -> *const c_char;
    fn octra_pvac_keygen(
        seed: *const u8,
        public_key: *mut *mut c_void,
        secret_key: *mut *mut c_void,
    ) -> i32;
    fn octra_pvac_free(value: *mut c_void, kind: i32);
    fn octra_pvac_decode(input: *const u8, size: usize, kind: i32, cap: bool) -> *mut c_void;
    fn octra_pvac_encode(value: *mut c_void, kind: i32, size: *mut usize) -> *mut u8;
    fn octra_pvac_free_bytes(value: *mut u8);
    fn octra_pvac_encrypt(
        pk: *mut c_void,
        sk: *mut c_void,
        amount: u64,
        seed: *const u8,
        zero: bool,
    ) -> *mut c_void;
    fn octra_pvac_decrypt(
        pk: *mut c_void,
        sk: *mut c_void,
        ct: *mut c_void,
        amount: *mut i64,
    ) -> i32;
    fn octra_pvac_add(
        pk: *mut c_void,
        left: *mut c_void,
        right: *mut c_void,
        subtract: bool,
    ) -> *mut c_void;
    fn octra_pvac_scale(pk: *mut c_void, ct: *mut c_void, factor: i64, math: bool) -> *mut c_void;
    fn octra_pvac_add_const(
        pk: *mut c_void,
        ct: *mut c_void,
        lo: u64,
        hi: u64,
        math: bool,
    ) -> *mut c_void;
    fn octra_pvac_commit(pk: *mut c_void, ct: *mut c_void, output: *mut u8) -> i32;
    fn octra_pvac_pedersen(amount: u64, blinding: *const u8, output: *mut u8) -> i32;
    #[cfg(feature = "benchmark")]
    fn octra_pvac_reference_add(pk: *mut c_void, ct: *mut c_void, iterations: usize) -> f64;
}

fn failure() -> Error {
    // Each synchronous call reads its own native thread-local error immediately.
    let (kind, message) = unsafe {
        (
            octra_pvac_error(),
            CStr::from_ptr(octra_pvac_error_message())
                .to_string_lossy()
                .into_owned(),
        )
    };
    if kind == 1 {
        Error::Rejected(message)
    } else {
        Error::Unavailable(if message.is_empty() {
            "pvac: native call failed".into()
        } else {
            message
        })
    }
}

struct Handle {
    pointer: NonNull<c_void>,
    kind: i32,
}

impl Handle {
    fn new(pointer: *mut c_void, kind: i32) -> Result<Self, Error> {
        Ok(Self {
            pointer: NonNull::new(pointer).ok_or_else(failure)?,
            kind,
        })
    }
    fn raw(&self) -> *mut c_void {
        self.pointer.as_ptr()
    }
    fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut size = 0;
        // C++ owns this allocation; free with its allocator even if copying panics.
        let pointer = unsafe { octra_pvac_encode(self.raw(), self.kind, &raw mut size) };
        let bytes = NativeBytes(NonNull::new(pointer).ok_or_else(failure)?);
        Ok(unsafe { std::slice::from_raw_parts(bytes.0.as_ptr(), size) }.to_vec())
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        // Unique ownership; Rust borrows prevent release during an operation.
        unsafe { octra_pvac_free(self.raw(), self.kind) };
    }
}

struct NativeBytes(NonNull<u8>);
impl Drop for NativeBytes {
    fn drop(&mut self) {
        unsafe { octra_pvac_free_bytes(self.0.as_ptr()) };
    }
}

pub struct PublicKey(Handle);
pub struct SecretKey(Handle);
pub struct Cipher(Handle);

pub fn keygen(seed: &[u8; 32]) -> Result<(PublicKey, SecretKey), Error> {
    let (mut public_key, mut secret_key) = (std::ptr::null_mut(), std::ptr::null_mut());
    let status =
        unsafe { octra_pvac_keygen(seed.as_ptr(), &raw mut public_key, &raw mut secret_key) };
    if status != 0 {
        return Err(failure());
    }
    Ok((
        PublicKey(Handle::new(public_key, 1)?),
        SecretKey(Handle::new(secret_key, 2)?),
    ))
}

fn decode(bytes: &[u8], kind: i32, cap: bool, maximum: usize) -> Result<Handle, Error> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(Error::Rejected(
            "pvac: input exceeds resource policy".into(),
        ));
    }
    Handle::new(
        unsafe { octra_pvac_decode(bytes.as_ptr(), bytes.len(), kind, cap) },
        kind,
    )
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        decode(bytes, 1, true, 5_000_000).map(Self)
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.0.encode()
    }
    pub fn encrypt(
        &self,
        secret: &SecretKey,
        amount: u64,
        seed: &[u8; 32],
    ) -> Result<Cipher, Error> {
        Handle::new(
            unsafe {
                octra_pvac_encrypt(self.0.raw(), secret.0.raw(), amount, seed.as_ptr(), false)
            },
            3,
        )
        .map(Cipher)
    }
    pub fn encrypt_zero(&self, secret: &SecretKey, seed: &[u8; 32]) -> Result<Cipher, Error> {
        Handle::new(
            unsafe { octra_pvac_encrypt(self.0.raw(), secret.0.raw(), 0, seed.as_ptr(), true) },
            3,
        )
        .map(Cipher)
    }
    pub fn decrypt(&self, secret: &SecretKey, cipher: &Cipher) -> Result<i64, Error> {
        let mut amount = 0;
        if unsafe {
            octra_pvac_decrypt(
                self.0.raw(),
                secret.0.raw(),
                cipher.0.raw(),
                &raw mut amount,
            )
        } != 0
        {
            return Err(failure());
        }
        Ok(amount)
    }
    pub fn add(&self, left: &Cipher, right: &Cipher) -> Result<Cipher, Error> {
        self.pair(left, right, false)
    }
    pub fn sub(&self, left: &Cipher, right: &Cipher) -> Result<Cipher, Error> {
        self.pair(left, right, true)
    }
    fn pair(&self, left: &Cipher, right: &Cipher, subtract: bool) -> Result<Cipher, Error> {
        Handle::new(
            unsafe { octra_pvac_add(self.0.raw(), left.0.raw(), right.0.raw(), subtract) },
            3,
        )
        .map(Cipher)
    }
    pub fn scale(&self, cipher: &Cipher, factor: i64, math: Math) -> Result<Cipher, Error> {
        Handle::new(
            unsafe {
                octra_pvac_scale(
                    self.0.raw(),
                    cipher.0.raw(),
                    factor,
                    matches!(math, Math::Active),
                )
            },
            3,
        )
        .map(Cipher)
    }
    pub fn add_const(
        &self,
        cipher: &Cipher,
        lo: u64,
        hi: u64,
        math: Math,
    ) -> Result<Cipher, Error> {
        Handle::new(
            unsafe {
                octra_pvac_add_const(
                    self.0.raw(),
                    cipher.0.raw(),
                    lo,
                    hi,
                    matches!(math, Math::Active),
                )
            },
            3,
        )
        .map(Cipher)
    }
    pub fn commitment(&self, cipher: &Cipher) -> Result<[u8; 32], Error> {
        let mut output = [0; 32];
        if unsafe { octra_pvac_commit(self.0.raw(), cipher.0.raw(), output.as_mut_ptr()) } != 0 {
            return Err(failure());
        }
        Ok(output)
    }
    #[cfg(feature = "benchmark")]
    pub fn reference_add_ns(&self, cipher: &Cipher, iterations: usize) -> Result<f64, Error> {
        let elapsed = unsafe { octra_pvac_reference_add(self.0.raw(), cipher.0.raw(), iterations) };
        if elapsed < 0.0 {
            Err(failure())
        } else {
            Ok(elapsed)
        }
    }
}

impl SecretKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        decode(bytes, 2, true, 1024).map(Self)
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.0.encode()
    }
}
impl Cipher {
    pub fn from_bytes(bytes: &[u8], cap: bool) -> Result<Self, Error> {
        decode(bytes, 3, cap, 1_048_576).map(Self)
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.0.encode()
    }
}

pub fn pedersen_commit(amount: u64, blinding: &[u8; 32]) -> Result<[u8; 32], Error> {
    let mut result = [0; 32];
    if unsafe { octra_pvac_pedersen(amount, blinding.as_ptr(), result.as_mut_ptr()) } != 0 {
        return Err(failure());
    }
    Ok(result)
}
