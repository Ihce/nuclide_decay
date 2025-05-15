//! Superset disassembly strategy with minimal overhead
//! 
//! Direct implementation based on the original high-performance code

use crate::{Address, Decoder, Disassembly, DisassemblyError, Insn};
use std::time::Instant;
use rayon::prelude::*;

/// Superset disassembly with minimal overhead
///
/// # Arguments
/// * `image` - The binary image to disassemble
/// * `decoder` - The decoder to use for disassembly
///
/// # Returns
/// A stream of disassembled instructions
pub fn run(image: &[u8], decoder: &dyn Decoder) -> Result<Disassembly, DisassemblyError> {
    println!("Starting superset disassembly on {} bytes", image.len());
    let start_time = Instant::now();
    
    // Pre-allocate a vector with a reasonable capacity
    let mut instructions = Vec::with_capacity(image.len() / 8);
    
    // Minimal version similar to your original code
    // Process in parallel and collect results
    let batch_size = 4096;  // Process in batches for better progress reporting
    let batch_count = (image.len() + batch_size - 1) / batch_size;
    
    println!("Processing {} batches", batch_count);
    
    for batch_idx in 0..batch_count {
        let batch_start = Instant::now();
        let start_offset = batch_idx * batch_size;
        let end_offset = std::cmp::min(start_offset + batch_size, image.len());
        
        println!("Processing batch {}/{} (offsets {}-{})", 
                 batch_idx + 1, batch_count, start_offset, end_offset);
        
        // Process this batch in parallel
        let batch_instructions: Vec<Insn> = (start_offset..end_offset)
            .into_par_iter()
            .filter_map(|offset| decoder.decode(image, offset as u64))
            .collect();
        
        let batch_count = batch_instructions.len();
        instructions.extend(batch_instructions);
        
        let batch_elapsed = batch_start.elapsed();
        if batch_elapsed.as_secs() > 0 {
            let batch_rate = batch_count as f64 / batch_elapsed.as_secs_f64();
            println!(
                "Batch {}: found {} instructions in {:?} ({:.0} insns/sec)",
                batch_idx + 1, batch_count, batch_elapsed, batch_rate
            );
        }
        
        // Show total progress
        let total_elapsed = start_time.elapsed();
        let progress = (end_offset as f64 / image.len() as f64) * 100.0;
        println!(
            "Overall progress: {:.1}% complete, found {} instructions in {:?}",
            progress, instructions.len(), total_elapsed
        );
    }
    
    // Sort by address for deterministic output
    instructions.sort_by_key(|insn| insn.addr);
    
    let elapsed = start_time.elapsed();
    let instr_per_sec = instructions.len() as f64 / elapsed.as_secs_f64();
    
    println!(
        "Superset disassembly completed in {:?}:", elapsed
    );
    println!("  - Found {} instructions ({:.0} instructions/sec)", 
             instructions.len(), instr_per_sec);
    
    Ok(Disassembly::Stream(instructions))
}