import urllib2
import json
from ghidra.util.task import TaskMonitor
from ghidra.app.decompiler import DecompInterface

# Your API Key
API_KEY = 'sk-XXXXX'

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
    url = 'https://api.openai.com/v1/chat/completions'
    
    # Prepare the data payload
    data = {
        "model": "gpt-4",
        "messages": [
            {"role": "user", "content": "Explain this code, help me understand what's happening at a high level. You're my Ghidra pal, and I'm a newbie. I want you to keep it brief, don't overwhelm me, and take educated guesses at what this code chunk does in the context of a binary being RE'd, and what it's overall job is, and then give me a quick breakdown of this code itself.Tell me what area (software, firmware, hardware) it relates to most likely, Then tell me how I could further explore the most interesting things discovered in it, guide me what to click or do in Ghidra.:\n{}".format(c_code)}
        ]
    }
    data = json.dumps(data)  # Convert dictionary to JSON string
    
    # Make the HTTP request
    req = urllib2.Request(
        url,
        data,
        {
            'Authorization': 'Bearer {}'.format(API_KEY),
            'Content-Type': 'application/json',
        }
    )
    
    # Receive the response and decode the JSON
    response = json.loads(urllib2.urlopen(req).read())
    
    # Check for errors
    if "error" in response:
        raise ValueError(response["error"])
    else:
        return response["choices"][0]["message"]["content"]

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
