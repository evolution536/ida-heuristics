# Heuristics plugin for IDA

Tim Blazytko created a really interesting [plugin](https://github.com/mrphrazer/obfuscation_detection) for Binary Ninja to detect potentially obfuscated code. I decided to port the heuristics in this plugin to IDA because it is a really useful plugin. It allows analysts to find leads to much more than just obfuscation. Encryption algorithms and C2 dispatching logic can be located using the heuristics as well. The heuristics are architecture-agnostic but the results might differ between architectures.

This is work in progress, as only a subset of the heuristics is implemented at the moment.

## Installation

Add `ida-heuristics.py` to the plugins directory of your IDA installation. Do not create a subdirectory, just place the Python script in the plugins dir.

## Usage

The plugin registers a menu under `Edit` -> `Heuristics` as shown in the image below. All features of the plugin can be accessed through these menu items.

![Heuristics plugin menu](https://github.com/evolution536/ida-heuristics/images/plugin_menu.png)

## Documentation

This section documents the heuristics the plugin features and what they can be used for.

### Large Basic Blocks

A basic block is a sequence of instructions referenced by, and running until a jump instruction. A basic block ends with an instruction that jumps to another basic block. Algorithms that implement many mathematical operations such as encryption tend to have large basic blocks. That means a basic block contains a lot of instructions that are executed before a jump instruction is encountered.

![Large basic block heuristic output](https://github.com/evolution536/ida-heuristics/images/large_basic_blocks.png)

### Cyclomatic Complexity

A metric from software development which indicates the number of paths a function can possible take from begin to end. While commonly executed on source code by static analysis tools to improve the quality of software, it can be used very well on disassembled code too. Functions with a high cyclomatic complexity may have many nested if-statements and loops.

![Cyclomatic complexity heuristic output](https://github.com/evolution536/ida-heuristics/images/cyclomatic_complexity.png)

### Frequently Called Functions

A simple but cool metric is which functions are called from other locations the most. Memory allocation and disposal functions are commonly called the most, but it might also be used to detect functions that dynamically hash and resolve Windows API functions.

![Frequently called functions heuristic output](https://github.com/evolution536/ida-heuristics/images/frequently_called_functions.png)

### Control Flow Flattening

Control Flow Flattening is a common obfuscation method that transforms an algorithm from its original form into an iterative algorithm that uses a state variable to determine which operations are called next. This way, the original code explodes in size and complexity and makes analysts' work harder. Flattened functions might be interesting to look at because the author probably has a reason to obfuscate that specific part of the code. This heuristic is quite expensive to compute and might take a minute to complete.

![Control flow flattening heuristic output](https://github.com/evolution536/ida-heuristics/images/control_flow_flattening.png)

### More to come. :)