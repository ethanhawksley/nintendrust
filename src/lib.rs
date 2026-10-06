pub mod bus;
mod cartridge;
mod controller;
pub mod cpu;
pub mod mappers;
mod opcodes;
mod palette;
pub mod ppu;
pub mod rom;

use crate::bus::Bus;
use crate::cpu::Cpu;
use crate::rom::Rom;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Emulator {
    cpu: Cpu,
    bus: Bus,
    rgba_buffer: Vec<u8>,
}

#[wasm_bindgen]
impl Emulator {
    #[wasm_bindgen(constructor)]
    pub fn new(rom_bytes: &[u8]) -> Emulator {
        let rom = Rom::new(&rom_bytes.to_vec());
        let mut bus = Bus::new(rom);
        let mut cpu = Cpu::new();
        cpu.reset(&mut bus);

        Emulator {
            cpu,
            bus,
            // Pre-allocate the buffer: 256 width * 240 height * 4 bytes (R,G,B,A)
            rgba_buffer: vec![0; 256 * 240 * 4],
        }
    }

    pub fn step_frame(&mut self) {
        self.bus.ppu.frame_complete = false;

        while !self.bus.ppu.frame_complete && !self.cpu.halted {
            self.cpu.emulate_cpu(&mut self.bus);
        }

        // Convert the NES u32 colors (0x00RRGGBB) to RGBA bytes for the HTML canvas
        for (i, &color) in self.bus.ppu.frame_buffer.iter().enumerate() {
            let r = ((color >> 16) & 0xFF) as u8;
            let g = ((color >> 8) & 0xFF) as u8;
            let b = (color & 0xFF) as u8;

            // Calculate the starting index for this pixel in the flat RGBA array
            let idx = i * 4;

            self.rgba_buffer[idx] = r; // Red
            self.rgba_buffer[idx + 1] = g; // Green
            self.rgba_buffer[idx + 2] = b; // Blue
            self.rgba_buffer[idx + 3] = 255; // Alpha (Opaque)
        }
    }

    pub fn set_input(&mut self, controller_state: u8) {
        self.bus.controller.controller1 = controller_state;
    }

    // Return a copy of the RGBA buffer to JS
    pub fn get_pixels(&self) -> Vec<u8> {
        self.rgba_buffer.clone()
    }
}
