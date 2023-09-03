# Ghidra-ChatGPT: A Ghidra Plugin that uses OpenAI's GPT to Explain Decompiled Functions
# Original Author: evyatar9 (https://github.com/evyatar9)
# Python 3 Port Author: wowitsjack (https://github.com/wowitsjack)
# Category: API
# Keybinding: Ctrl-Alt-G
# Menu Path: Tools.Ghidra-ChatGPT

# Import Required Libraries
import urllib2  # For making HTTP requests
import json  # For JSON encoding and decoding
from ghidra.util.task import TaskMonitor  # For task monitoring in Ghidra
from ghidra.app.decompiler import DecompInterface  # For decompiling functions in Ghidra

# API Key for OpenAI GPT (Replace with your actual key)
API_KEY = 'sk-XXXXXXX'


# Function to Ask GPT to Explain C Code
def explainFunction(c_code):
    """
    Calls OpenAI's GPT to explain the given C code.
    
    Args:
        c_code (str): The C code to be explained.
        
    Returns:
        str: GPT's explanation of the code.
    """
    
    # API URL
    url = 'https://api.openai.com/v1/completions'
    
    # Prepare the data payload
    data = {"prompt": "Explain this code, this is for an extremely technical university comp-sci class. You need to give as much detail as you can, and make sure I understand, and not exclude anything. This is for critical reverse-enginereing work. Here is the code from Ghidra:\n" + c_code, "max_tokens": 2048, "model": "text-davinci-003"}
    data = json.dumps(data)  # Convert dictionary to JSON string
    
    # Make the HTTP request
    req = urllib2.Request(
        url,
        data,
        {
            'Authorization': 'Bearer {}'.format(API_KEY),  # Authorization header
            'Content-Type': 'application/json',  # Data type
        },
    )
    
    # Receive the response and decode the JSON
    response = json.loads(urllib2.urlopen(req).read())
    
    # Check for errors
    if "error" in response:
        raise ValueError(response["error"])
    else:
        return response["choices"][0]["text"]  # Return the explanation


# Function to Get the Currently Decompiled Function
def getCurrentDecompiledFunction():
    """
    Retrieves the decompiled C code of the current function in Ghidra.
    
    Returns:
        str: Decompiled C code of the current function.
    """
    
    # Create a Dummy TaskMonitor
    monitor = TaskMonitor.DUMMY
    
    # Initialize the DecompInterface
    decompiler = DecompInterface()
    
    # Set the program for DecompInterface
    decompiler.openProgram(currentProgram)
    
    # Get the current function address
    currentAddress = currentLocation.getAddress()
    
    # Fetch the function containing the current address
    function = getFunctionContaining(currentAddress)
    
    # If no function, raise an error
    if function is None:
        raise ValueError("No function is currently selected.")
    
    # Try to decompile the function and get the C code
    try:
        return decompiler.decompileFunction(function, 30, monitor).getDecompiledFunction().getC()
    except Exception as e:
        raise ValueError("Unable to decompile function: {}".format(str(e)))


# Main Execution
try:
    # Get the decompiled C code
    c_code = getCurrentDecompiledFunction()
    
    # Ask GPT for an explanation
    explanation = explainFunction(c_code)
    
    # Print the explanation
    print(explanation)
    
except ValueError as e:
    # Print any errors
    print(e)
