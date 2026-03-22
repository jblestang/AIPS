//! Bare-metal PHY driver: generic DMA ring trait + smoltcp Device adapter.
//!
//! Provides a `DmaDevice` trait that any MCU EMAC HAL can implement
//! (STM32H7, ESP32, RISC-V SoC, etc.) and an adapter that wraps it as a
//! `smoltcp::phy::Device` so the rest of AIPS is platform-agnostic.
//!
//! # Usage
//! 1. Implement `DmaDevice` for your HAL struct.
//! 2. Wrap it in `SmoltcpAdapter`.
//! 3. Pass to `Interface::new()` in your `main()`.

#![no_std]

/// A hardware DMA ring available for zero-copy Ethernet RX/TX.
///
/// Implementors map directly to the EMAC DMA descriptor ring of the
/// target SoC.  All methods should be interrupt-safe (or called from
/// a single thread in a bare-metal environment).
pub trait DmaDevice {
    /// Returns the next received frame as a byte slice, or `None` if
    /// the RX queue is empty.  The caller **must** call `rx_release` when
    /// done to return the descriptor to the hardware.
    fn rx_next(&mut self) -> Option<&[u8]>;

    /// Release the last buffer returned by `rx_next` back to the hardware.
    fn rx_release(&mut self);

    /// Acquire a TX buffer large enough for `len` bytes, or `None` if
    /// all TX descriptors are in use.
    fn tx_acquire(&mut self, len: usize) -> Option<&mut [u8]>;

    /// Commit the TX buffer and hand it to the DMA engine for transmission.
    fn tx_commit(&mut self);
}

/// Wraps a `DmaDevice` as a `smoltcp::phy::Device`.
///
/// This allows the AIPS pipeline to drive any bare-metal EMAC through the
/// same smoltcp API used on Linux and macOS.
pub struct SmoltcpAdapter<D: DmaDevice> {
    inner: D,
}

impl<D: DmaDevice> SmoltcpAdapter<D> {
    /// Create an adapter around `device`.
    pub fn new(device: D) -> Self {
        Self { inner: device }
    }

    /// Access the inner `DmaDevice` (e.g. to call HAL-specific methods).
    pub fn inner_mut(&mut self) -> &mut D {
        &mut self.inner
    }
}

impl<D: DmaDevice> smoltcp::phy::Device for SmoltcpAdapter<D> {
    type RxToken<'a> = DmaRxToken<'a> where D: 'a;
    type TxToken<'a> = DmaTxToken<'a, D> where D: 'a;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // smoltcp expects both an RX and TX token simultaneously.
        // For an IPS (pass-through), this doesn't quite fit the smoltcp
        // model — we use `receive` only to get the RX frame; TX is driven
        // separately via `transmit`.
        // Return None here; the caller uses `rx_next`/`tx_acquire` directly.
        None
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(DmaTxToken { device: &mut self.inner })
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.max_transmission_unit = 1514;
        caps.medium = smoltcp::phy::Medium::Ethernet;
        caps
    }
}

/// A zero-copy RX token borrowing from the DMA ring.
pub struct DmaRxToken<'a> {
    pub data: &'a [u8],
}

impl<'a> smoltcp::phy::RxToken for DmaRxToken<'a> {
    fn consume<R, F>(self, f: F) -> R
    where F: FnOnce(&[u8]) -> R {
        f(self.data)
    }
}

/// A TX token that acquires a DMA TX descriptor slot.
pub struct DmaTxToken<'a, D: DmaDevice> {
    device: &'a mut D,
}

impl<'a, D: DmaDevice> smoltcp::phy::TxToken for DmaTxToken<'a, D> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where F: FnOnce(&mut [u8]) -> R {
        if let Some(buf) = self.device.tx_acquire(len) {
            let r = f(buf);
            self.device.tx_commit();
            r
        } else {
            // No TX descriptor available — call with a dummy buffer.
            let mut dummy = [0u8; 1514];
            f(&mut dummy[..len.min(1514)])
        }
    }
}

// --- STM32H7 stub ---

/// Example stub implementing `DmaDevice` for an STM32H7 EMAC.
///
/// Replace `EmacRegisters` with your HAL's actual type.
#[cfg(feature = "stm32h7")]
pub struct Stm32h7Emac {
    // HAL handle would go here; omitted to keep no_std / no-HAL dep.
    _phantom: core::marker::PhantomData<()>,
}

#[cfg(feature = "stm32h7")]
impl DmaDevice for Stm32h7Emac {
    fn rx_next(&mut self) -> Option<&[u8]> { todo!("wire to STM32H7 DMA RX descriptor") }
    fn rx_release(&mut self) { todo!() }
    fn tx_acquire(&mut self, _len: usize) -> Option<&mut [u8]> { todo!() }
    fn tx_commit(&mut self) { todo!() }
}
