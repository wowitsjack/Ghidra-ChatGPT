# Ghidra-ChatGPT

Ghidra-ChatGPT is a specialized Ghidra plugin designed to utilize the machine learning capabilities of [OpenAI's GPT](https://chat.openai.com/chat) for semantic analysis of decompiled functions. This provides a nuanced understanding of codebase functionality.

![Example Illustration](images/example.gif)

## Prerequisites

- Ghidra, version `>= 10.1.5` ([Official Site](https://ghidra-sre.org))
- API key for OpenAI's GPT, obtainable from [OpenAI API](https://beta.openai.com/account/api-keys)

## Installation Procedure

1. **Acquire Script**: Download the Python script [Ghidra-ChatGPT.py](./Ghidra-ChatGPT.py).
2. **Invoke Script Manager**: Within Ghidra, go to `Window` > `Script Manager`.
3. **Instantiate New Script**: Click `New`, select `Python` as the language, and designate the script name as `Ghidra-ChatGPT.py`.
4. **Incorporate Code**: Copy the code from [Ghidra-ChatGPT.py](./Ghidra-ChatGPT.py) into the editor. Substitute `API_KEY = ''` with the acquired OpenAI API key.
5. **Persist Script**: Save the script by clicking the `Save` button.
6. **Activate in Tools Menu**: In the Script Manager, locate your newly saved script and tick the 'In Tools Menu' checkbox.

## Operational Guidelines

To invoke Ghidra-ChatGPT, adhere to one of the following procedures:

1. **Keyboard Shortcut**: Execute `Ctrl + Alt + G` (modifiable within the script).

   **- OR -**

2. **Menu Navigation**: Traverse to `Tools -> Ghidra-ChatGPT`.

Upon activation, the plugin will conduct semantic analysis on the selected function and output the findings to the Ghidra console.

## Contributions
- Original script by evyatar9
- Port to Python 3 executed by wowitsjack

## Contribution Guidelines

To contribute to the Ghidra-ChatGPT project, kindly submit pull requests or report issues through the [Ghidra-ChatGPT GitHub repository](https://github.com/your-repo/Ghidra-ChatGPT).

## Referential Material

- [Decompiler Interface in Ghidra Documentation](https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html)
- [OpenAI API Guidelines](https://beta.openai.com/docs/)
