# Example Python script demonstrating nuclide_decay output formats
import nuclide_decay as nd
import json
import os
import sys
import argparse
import time
import signal
import psutil
import resource

# Global for signal handling
should_exit = False

def signal_handler(sig, frame):
    global should_exit
    print(f"\nReceived signal {sig}, gracefully exiting...")
    should_exit = True

# Set up signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def check_file(file_path):
    """Validate the input file"""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if not os.path.isfile(file_path):
        raise ValueError(f"Not a file: {file_path}")
    
    file_size = os.path.getsize(file_path)
    print(f"File size: {file_size / (1024*1024):.2f} MB")
    
    if file_size > 100 * 1024 * 1024:  # 100 MB
        print("Warning: Large file may cause performance issues")
    
    # Check if file is executable
    try:
        is_executable = os.access(file_path, os.X_OK)
        print(f"File is executable: {is_executable}")
    except Exception as e:
        print(f"Could not check executable permission: {e}")
    
    return file_size

def monitor_resources():
    """Print current resource usage"""
    process = psutil.Process(os.getpid())
    memory_info = process.memory_info()
    
    print(f"Memory usage: {memory_info.rss / (1024*1024):.2f} MB")
    
    # CPU time
    cpu_times = process.cpu_times()
    print(f"CPU time (user/system): {cpu_times.user:.2f}s / {cpu_times.system:.2f}s")
    
    # Check soft resource limits (memory)
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    print(f"Memory limit: {'unlimited' if soft == -1 else f'{soft/(1024*1024*1024):.2f} GB'}")

def main():
    parser = argparse.ArgumentParser(description='Disassemble a binary file using nuclide_decay')
    parser.add_argument('binary_file', help='Path to the binary file to disassemble')
    parser.add_argument('--strategy', '-s', default='linear',
                      choices=['linear', 'recursive', 'superset', 'probabilistic'],
                      help='Disassembly strategy')
    parser.add_argument('--output-format', '-o', default='text',
                      choices=['text', 'json', 'jsonl', 'csv', 'ngram'],  # Removed 'protobuf'
                      help='Output format')
    parser.add_argument('--output-file', '-f', help='Write output to file instead of stdout')
    parser.add_argument('--ngram-size', '-n', type=int, default=3,
                      help='Size of n-grams (for ngram output format)')
    parser.add_argument('--include-operands', action='store_true',
                      help='Include operands in n-grams (for ngram output format)')
    parser.add_argument('--timeout', '-t', type=int, default=120,
                      help='Timeout in seconds (default: 120)')
    args = parser.parse_args()

    try:
        # Check file validity
        print(f"Checking file: {args.binary_file}")
        file_size = check_file(args.binary_file)
        
        # Print initial resource usage
        print("\nInitial resource state:")
        monitor_resources()
        
        # Set a timeout
        start_time = time.time()
        timeout_seconds = args.timeout
        
        print(f"\nBeginning disassembly with strategy: {args.strategy}")
        print(f"Output format: {args.output_format}")
        
        # Disassemble the file with timeout handling
        result = None
        
        while True:
            # Check if we should exit gracefully
            if should_exit:
                print("Disassembly canceled by user.")
                return 1
                
            # Check timeout
            elapsed = time.time() - start_time
            if elapsed > timeout_seconds:
                print(f"Error: Disassembly timed out after {elapsed:.1f} seconds")
                return 1
                
            # Only check every few seconds to avoid overhead
            if elapsed % 5 < 0.1:  # Check roughly every 5 seconds
                print(f"Disassembly running for {elapsed:.1f} seconds...")
                monitor_resources()
            
            # Try to fetch result with a small internal timeout
            try:
                # Use signal.alarm as a safety backup timeout (UNIX only)
                if hasattr(signal, 'SIGALRM'):
                    signal.signal(signal.SIGALRM, signal_handler)
                    signal.alarm(5)  # 5 second internal progress check
                
                # Actually call the disassembler
                if result is None:  # Only call once
                    result = nd.disassemble_file(
                        args.binary_file,
                        strategy=args.strategy,
                        output_format=args.output_format,
                        ngram_size=args.ngram_size,
                        include_operands=args.include_operands
                    )
                    # Disable alarm if we got here
                    if hasattr(signal, 'SIGALRM'):
                        signal.alarm(0)
                    break  # Successfully got result, exit the loop
                    
            except Exception as e:
                # Cancel alarm if it was set
                if hasattr(signal, 'SIGALRM'):
                    signal.alarm(0)
                    
                # Only exit if it's a real error, not our timeout
                if not should_exit:
                    print(f"Error during disassembly: {e}")
                    return 1
            
            # Small sleep to avoid tight loop
            time.sleep(0.1)
        
        print(f"Disassembly completed in {time.time() - start_time:.2f} seconds")
        print("\nFinal resource state:")
        monitor_resources()

        # Handle the output
        if args.output_file:
            # Write to file
            with open(args.output_file, 'w') as f:
                f.write(result)
            print(f"Output written to {args.output_file}")
        else:
            # Write to stdout (possibly truncated if very large)
            result_len = len(result)
            if result_len > 10000:
                print(f"{result[:5000]}\n...\n[{result_len - 10000} characters truncated]...\n{result[-5000:]}")
            else:
                print(result)
                
        # For JSON and N-gram outputs, optionally pretty-print
        if args.output_format in ['json', 'ngram'] and not args.output_file:
            # Already printed the raw output, now show a prettier version
            try:
                data = json.loads(result)
                print("\n--- Prettier JSON output: ---")
                # Only print first few items if it's a large array
                if isinstance(data, list) and len(data) > 10:
                    print(f"[Showing 10/{len(data)} items]")
                    print(json.dumps(data[:10], indent=2))
                    print("...")
                else:
                    print(json.dumps(data, indent=2))
            except json.JSONDecodeError as e:
                # Not valid JSON, show the error
                print(f"Note: Could not pretty-print JSON: {e}")
                pass
                
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())