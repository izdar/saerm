import json
from collections import defaultdict

data = []

with open("runtime_monitor.txt", "r") as f:
    data = f.readlines()

def clean_element(elem):
    """Thoroughly clean a single trace element"""
    return elem.replace('(', '').replace(')', '').replace('\n', '').strip()

def parse_trace_lines(data):
    trace = defaultdict(list)
    
    for line in data:
        # Find first opening parenthesis
        idx = line.find("(")
        
        if idx == -1:
            continue
            
        # Extract the violation ID (everything before first parenthesis)
        violation_id = line[:idx].strip()
        
        # Process the trace part
        trace_part = line[idx:]
        
        # Handle the special case where closing and opening parentheses are adjacent
        # Replace ") (" with a special marker, then split
        trace_part = trace_part.replace(") (", "###SPLIT###")
        
        # Now remove all parentheses and newlines
        trace_part = clean_element(trace_part)
        
        # Split by our marker
        elements = trace_part.split("###SPLIT###")
        
        # Clean each element
        clean_elements = [elem for elem in elements if elem.strip()]
        
        if clean_elements:
            trace[violation_id].append(clean_elements)
    
    return trace

def is_prefix(list1, list2):
    """Check if list1 is a prefix of list2"""
    if len(list1) > len(list2):
        return False
    
    return all(list1[i] == list2[i] for i in range(len(list1)))

def filter_by_prefix(list_of_lists):
    """Keep only the shortest lists that are prefixes of longer lists,
    or lists that don't share common prefixes with any other list"""
    if not list_of_lists:
        return []
    
    # Sort by length (shortest first)
    sorted_lists = sorted(list_of_lists, key=len)
    result = []
    
    for current_list in sorted_lists:
        # Skip empty lists
        if not current_list:
            continue
            
        # Check if any list already in result is a prefix of current_list
        prefix_found = False
        for existing in result:
            if is_prefix(existing, current_list):
                prefix_found = True
                break
                
        if prefix_found:
            continue
                
        # Remove any longer lists that current_list is a prefix of
        result = [lst for lst in result if not is_prefix(current_list, lst)]
        result.append(current_list)
    
    return result

# Main process
def process_trace_data(data):
    # Parse data into the trace dictionary
    trace = parse_trace_lines(data)
    
    # Apply prefix filtering to each violation group
    for violation_id in trace:
        trace[violation_id] = filter_by_prefix(trace[violation_id])
    
    return trace

def count_all_traces(trace_dict):
    """
    Count all traces in the dictionary
    
    Args:
        trace_dict: A dictionary where keys are violation IDs and values are lists of trace lists
        
    Returns:
        total_count: Total number of traces
        counts_per_violation: Dictionary with counts for each violation ID
    """
    total_count = 0
    counts_per_violation = {}
    
    for violation_id, trace_lists in trace_dict.items():
        # Count traces for this violation ID
        violation_count = len(trace_lists)
        counts_per_violation[violation_id] = violation_count
        
        # Add to total count
        total_count += violation_count
    
    return total_count, counts_per_violation


trace = process_trace_data(data)
print(count_all_traces(trace))
with open("../runtime_prefix_filter.json", "w") as f:
    json.dump(trace, f)