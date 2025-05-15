//! Python bindings for nuclide_decay disassembler

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use pyo3::exceptions::{PyValueError, PyIOError};
use crate::format::{OutputFormat, NgramParams};
use crate::{
    parser::GoblinParser,
    decoder::CapstoneDecoder,
    strategy::Strategy,
    BinaryParser,
};

/// Disassemble binary data with specified strategy and output format
#[pyfunction]
#[pyo3(signature = (
    binary_data,
    strategy="linear", 
    output_format="text", 
    ngram_size=3, 
    include_operands=false
))]
fn disassemble(
    py: Python<'_>,
    binary_data: Vec<u8>, // Change to Vec<u8> for automatic conversion
    strategy: &str, 
    output_format: &str,
    ngram_size: usize,
    include_operands: bool,
) -> PyResult<String> {
    // Binary data is already a Vec<u8>
    let bytes = binary_data.as_slice();
    
    // Parse binary
    let parser = GoblinParser::new();
    let metadata = parser.parse(bytes)
        .map_err(|e| PyValueError::new_err(format!("Failed to parse binary: {}", e)))?;
    
    // Create decoder
    let decoder = CapstoneDecoder::for_architecture(metadata.architecture)
        .map_err(|e| PyValueError::new_err(format!("Failed to create decoder: {}", e)))?;
    
    // Select strategy
    let strategy = match strategy.to_lowercase().as_str() {
        "linear" => Strategy::Linear,
        "recursive" => Strategy::Recursive,
        "superset" => Strategy::Superset,
        "probabilistic" => Strategy::Probabilistic,
        _ => return Err(PyValueError::new_err(format!("Unknown strategy: {}", strategy))),
    };
    
    // Parse output format
    let output_format = match output_format.to_lowercase().as_str() {
        "text" => OutputFormat::Text,
        "json" => OutputFormat::Json,
        "jsonl" | "jsonlines" => OutputFormat::JsonLines,
        "csv" => OutputFormat::Csv,
        "ngram" | "ngrams" => OutputFormat::Ngram,
        _ => return Err(PyValueError::new_err(format!("Unknown output format: {}", output_format))),
    };
    
    // Configure n-gram parameters if needed
    let ngram_params = if output_format == OutputFormat::Ngram {
        Some(NgramParams {
            n: ngram_size,
            include_operands,
        })
    } else {
        None
    };
    
    // Get a formatter for the selected output format
    let formatter = output_format.get_formatter(ngram_params);
    
    // Collect and format results from all executable sections
    let mut all_output = String::new();
    
    for (region_data, base_addr) in metadata.get_executable_data(bytes) {
        let disassembly = strategy.run(region_data, &decoder)
            .map_err(|e| PyValueError::new_err(format!("Disassembly failed: {}", e)))?;
        
        let output = formatter.format(&disassembly, base_addr)
            .map_err(|e| PyValueError::new_err(format!("Failed to format output: {}", e)))?;
        
        all_output.push_str(&output);
        
        // Add section separator for text output
        if output_format == OutputFormat::Text && !all_output.ends_with("\n\n") {
            all_output.push_str("\n\n");
        }
    }
    
    Ok(all_output)
}

/// Disassemble a file with specified strategy and output format
#[pyfunction]
#[pyo3(signature = (
    file_path, 
    strategy="linear", 
    output_format="text", 
    ngram_size=3, 
    include_operands=false
))]
fn disassemble_file(
    py: Python<'_>,
    file_path: &str, 
    strategy: &str, 
    output_format: &str,
    ngram_size: usize,
    include_operands: bool,
) -> PyResult<String> {
    let bytes = std::fs::read(file_path)
        .map_err(|e| PyIOError::new_err(format!("Failed to read file {}: {}", file_path, e)))?;
    
    // Call the disassemble function with the raw bytes
    println!("RUST: Disassembling file: {}", file_path);
    disassemble(py, bytes, strategy, output_format, ngram_size, include_operands)
}

/// Python module initialization
#[pymodule]
fn nuclide_decay(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Add module level functions
    m.add_function(wrap_pyfunction!(disassemble, m)?)?;
    m.add_function(wrap_pyfunction!(disassemble_file, m)?)?;
    
    // Create the OutputFormat class as a dict
    let py = m.py();
    let output_format = PyDict::new_bound(py);
    output_format.set_item("TEXT", "text")?;
    output_format.set_item("JSON", "json")?;
    output_format.set_item("JSONL", "jsonl")?;
    output_format.set_item("CSV", "csv")?;
    output_format.set_item("NGRAM", "ngram")?;
    m.setattr("OutputFormat", output_format)?;
    
    // Create the Strategy class as a dict
    let strategy = PyDict::new_bound(py);
    strategy.set_item("LINEAR", "linear")?;
    strategy.set_item("SUPERSET", "superset")?;
    strategy.set_item("RECURSIVE", "recursive")?;
    strategy.set_item("PROBABILISTIC", "probabilistic")?;
    m.setattr("Strategy", strategy)?;
    
    Ok(())
}   