//! Linear-sweep disassembly strategy with parallel processing

use crate::{Address, Decoder, Disassembly, DisassemblyError, Insn, MAX_INSTRUCTION_SIZE};
use std::time::Instant;
use rayon::prelude::*;

/// Maximum chunk size for parallel processing
const CHUNK_SIZE: usize = 4096;

/// Linear-sweep disassembly with parallel processing
///
/// # Arguments
/// * `image` - The binary image to disassemble
/// * `decoder` - The decoder to use for disassembly
///
/// # Returns
/// A stream of disassembled instructions
pub fn run(image: &[u8], decoder: &dyn Decoder) -> Result<Disassembly, DisassemblyError> {
    println!("Starting parallel linear sweep on {} bytes", image.len());
    let start_time = Instant::now();
    
    // No need to process if image is empty
    if image.is_empty() {
        return Ok(Disassembly::Stream(Vec::new()));
    }
    
    // Determine how many chunks to break the binary into
    let image_len = image.len();
    let overlap = MAX_INSTRUCTION_SIZE;
    let effective_chunk_size = CHUNK_SIZE;
    let num_chunks = (image_len + effective_chunk_size - 1) / effective_chunk_size;
    
    println!("Processing {} bytes in {} chunks", image_len, num_chunks);
    
    // Process each chunk in parallel
    let chunk_results: Vec<Vec<Insn>> = (0..num_chunks)
        .into_par_iter()
        .map(|chunk_idx| {
            let chunk_start = chunk_idx * effective_chunk_size;
            let chunk_end = std::cmp::min(chunk_start + effective_chunk_size + overlap, image_len);
            
            // Process this chunk with linear sweep
            process_chunk(image, decoder, chunk_start, chunk_end, chunk_idx)
        })
        .collect();
    
    // Combine results from all chunks
    let mut all_instructions = Vec::new();
    let mut total_skipped = 0;
    
    for (chunk_idx, insns) in chunk_results.into_iter().enumerate() {
        let chunk_start = chunk_idx * effective_chunk_size;
        let chunk_end = std::cmp::min(chunk_start + effective_chunk_size, image_len);
        
        // Only include instructions that start within this chunk's primary range
        // (not the overlap region)
        for insn in insns {
            if insn.addr >= chunk_start as Address && insn.addr < chunk_end as Address {
                all_instructions.push(insn);
            } else {
                total_skipped += 1;
            }
        }
    }
    
    // Sort instructions by address
    all_instructions.sort_by_key(|insn| insn.addr);
    
    let elapsed = start_time.elapsed();
    let instr_per_sec = all_instructions.len() as f64 / elapsed.as_secs_f64();
    let bytes_per_sec = image_len as f64 / elapsed.as_secs_f64();
    
    println!(
        "Parallel linear sweep completed in {:?}:", elapsed
    );
    println!("  - Found {} instructions ({:.0} instructions/sec)", 
             all_instructions.len(), instr_per_sec);
    println!("  - Throughput: {:.0} bytes/sec", bytes_per_sec);
    println!("  - Excluded {} instructions from overlap regions", total_skipped);
    
    Ok(Disassembly::Stream(all_instructions))
}

/// Process a single chunk with linear sweep
fn process_chunk(
    image: &[u8], 
    decoder: &dyn Decoder, 
    start_offset: usize, 
    end_offset: usize,
    chunk_idx: usize
) -> Vec<Insn> {
    // Adjust bounds to ensure we're within the image
    let start = start_offset;
    let end = std::cmp::min(end_offset, image.len());
    
    // Create a thread-local start time
    let chunk_start_time = Instant::now();
    
    let mut insns = Vec::new();
    let mut at: Address = start as Address;
    let end_addr = end as Address;
    
    // Counters for this chunk
    let mut instruction_count = 0;
    let mut skip_count = 0;
    
    while at < end_addr {
        if let Some(i) = decoder.decode(image, at) {
            let size = i.size as Address;
            if size == 0 {
                // Avoid infinite loop from zero-sized instructions
                at += 1;
                skip_count += 1;
            } else {
                insns.push(i);
                at += size;
                instruction_count += 1;
            }
        } else {
            // Couldn't decode an instruction, skip one byte
            at += 1;
            skip_count += 1;
        }
        
        // Periodic progress reporting for long-running chunks
        if instruction_count % 1000 == 0 && chunk_start_time.elapsed().as_secs() >= 1 {
            let progress = (at - start as Address) as f64 / (end_addr - start as Address) as f64 * 100.0;
            println!(
                "Chunk {}: {:.1}% complete, found {} instructions so far",
                chunk_idx, progress, instruction_count
            );
        }
    }
    
    // Final progress for this chunk
    if chunk_start_time.elapsed().as_secs() >= 1 {
        println!(
            "Chunk {} completed in {:?}: found {} instructions, skipped {} bytes",
            chunk_idx, chunk_start_time.elapsed(), instruction_count, skip_count
        );
    }
    
    insns
}