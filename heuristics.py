import os
import re
import idc
import idaapi
import ida_diskio
import idautils
import ida_bytes

# Global definitions.
VERSION = "1.0"

# Set initialized flag to false to begin with.
p_initialized = False

# Returns the index of the last element in the result list that falls within the 95th percentile or higher.
def get_95th_percentile(results):
	threshold = results[3] * 0.05
	slider = 0
	num = 0
	while slider < threshold:
		num += 1
		slider += results[0][num][1][1]
	return num

# Counts the number of instructions inside a function, taking into account that it might have multiple chunks.
def count_function_instructions(func_ea):
	# Keep track of total number of instructions in function.
	insn_count = 0

	# Get chunks in this function.
	for (start_ea, end_ea) in idautils.Chunks(func_ea):
		if start_ea == end_ea:
			continue

		# Increment instruction counter and move to next head.
		head = idc.next_head(start_ea)
		chunk_insn_count = 0
		while head < end_ea:
			chunk_insn_count += 1
			head = idc.next_head(head)

		# When done, add the instruction count inside this chunk to the total counter.
		insn_count += chunk_insn_count

	# Return total instruction count for the entire function.
	return insn_count

# Computes large basic blocks score for given function.
def func_large_basic_blocks(func_ea):
	# Get object reference to function.
	func_ptr = idaapi.get_func(func_ea)

	# Get flow chart of the function containing all basic blocks.
	# https://moritzraabe.de/2017/01/15/ida-pro-anti-disassembly-basic-blocks-and-idapython/
	flowchart = idaapi.FlowChart(func_ptr)

	# Get number of instructions inside the function.
	insn_count = count_function_instructions(func_ea)

	# Compute number of instructions divided by the number of basic blocks.
	return insn_count / max(1, flowchart.size)

# Scoring function that computes the cyclomatic complexity metric of given function.
def func_cyclomatic_complexity(func_ea):
	# Get object reference to function.
	func_ptr = idaapi.get_func(func_ea)

	# Get flow chart of the function containing all basic blocks.
	# https://moritzraabe.de/2017/01/15/ida-pro-anti-disassembly-basic-blocks-and-idapython/
	flowchart = idaapi.FlowChart(func_ptr, flags=idaapi.FC_PREDS | idaapi.FC_NOEXT)

	# Calculate number of edges inside the function by looking at predecessors and successors.
	edges = 0
	for block in flowchart:
		for succ in block.succs():
			edges += 1
		for pred in block.preds():
			edges += 1

	# Compute the cyclomatic complexity for this function.
	# We set the minimum value to 1, because in some heavily obfuscated binary files,
	# functions are not always parsed correctly and a couple of not-connected basic blocks
	# may reside in the function. In such a case, we would get a negative value that
	# screws up the statistics. Those are outliers and we will remove them this way.
	return max(1, edges - flowchart.size + 2)

# Calculates the numberof cross references to a given function.
def func_get_xrefs(func_ea):
	return len(list(idautils.XrefsTo(func_ea)))

# Gets tree of blocks dominated by a given basic block.
def get_blocks_dominated_by(block):
	result = set()
	worklist = [ block ]

	# Get successing blocks. We perform a depth-first search to get the entire tree.
	while worklist:
		next_block = worklist.pop(0)
		result.add(next_block.start_ea)

		# Get all successing blocks and add them to the worklist.
		for succ in next_block.succs():
			# Test whether we have already visited this block. If so, we will not add it to the results.
			if succ.start_ea in result:
				continue

			# Not visited yet, so add the successor to the worklist.
			worklist.append(succ)

	# Return the successors, or the dominated basic blocks.
	return result

# Computes control flow flattening score for given function.
def func_control_flow_flattening(func_ea):
	# Initialize score to zero.
	score = 0.0

	# Get object reference to function.
	func_ptr = idaapi.get_func(func_ea)

	# Get flow chart of the function containing all basic blocks.
	# https://moritzraabe.de/2017/01/15/ida-pro-anti-disassembly-basic-blocks-and-idapython/
	flowchart = idaapi.FlowChart(func_ptr, flags=idaapi.FC_PREDS | idaapi.FC_NOEXT)

	# Iterate over all blocks in this function and compute the score.
	for block in flowchart:
		# Get blocks dominated by the current one.
		dominated = get_blocks_dominated_by(block)

		# Test for a back edge in the tree of dominated blocks. That means, if there exists an edge
		# between any of the successing blocks back to the currently examined block, there is a cycle
		# and, assuming that the current block is the 'controller', the dominated block flows back there.
		if not any(b.start_ea in dominated and b.start_ea != block.start_ea for b in block.preds()):
			# None found, so this control flow path has a low probability of being flattened.
			continue

		# Compute the score with this block.
		score = max(score, len(dominated) / flowchart.size)

	# Return the accumulated score.
	return score

# Get dictionary of stack members of specified function.
def get_stack_variables(func_ea):
	members = {}
	base = None

	# Get stack frame.
	frame = idc.get_func_attr(func_ea, idc.FUNCATTR_FRAME)

	# Ignore functions that (don't have a stack frame at all I guess?).
	if frame == idc.BADADDR:
		return members, base

	# Iterate frame structure members and save them in the output.
	for frame_member in idautils.StructMembers(frame):
		member_offset, member_name, _ = frame_member
		members[member_name] = member_offset
		if member_name == ' r':
			base = member_offset
	return members, base

# Gets list of cross references to stack variables in function.
def get_stack_references(func_ea, members, stack_base):
	refs = {}
	for func_item in idautils.FuncItems(func_ea):
		flags = ida_bytes.get_full_flags(func_item)
		stkvar = 0 if ida_bytes.is_stkvar0(flags) else 1 if ida_bytes.is_stkvar1(flags) else None
		if stkvar is None:
			continue

		# Get operand that references the stack location as a string. We will split locations ourselves.
		opnd = idc.print_operand(func_item, stkvar).replace('[', '').replace(']', '')

		# Split the sub-operands from the memory locator.
		m = re.split(r'[+*-]', opnd)
		for x in m:
			# Test whether one of the fake offsets reside in this instruction.
			if x in members:
				# Add it to the dictionary if not already there.
				if x not in refs:
					refs[x] = [ func_item ]
				else:
					refs[x].append(func_item)

	return refs

# Computes wrong stack frame score for given function.
def func_wrong_stack_frame(func_ea):
	# Initialize score to zero.
	score = 0.0

	# Get stack members first.
	members, base = get_stack_variables(func_ea)

	# Get cross references to those stack members.
	total_refs = 0
	refs = get_stack_references(func_ea, members, base)
	for v, r in refs.items():
		if len(r) == 0:
			continue
		else: total_refs += len(r)

	# FIXME: see which type of metric would do best here.
	return len(members) / max(1, total_refs)

# Iterates over segments and functions, executing a scoring function and tracking the metrics.
def iterate_functions_and_track_statistics(proc):
	# Create dictionary that will keep track of functions and metrics.
	metric_dict = {}
	sum_of_metrics = 0
	min_metric = 0xFFFFFFFF
	max_metric = 0

	# Get all segments.
	seg_ea = idc.get_first_seg()
	while seg_ea != idc.BADADDR:
		# Get all functions within this segment.
		for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
			# Get function name.
			func_name = idc.get_func_name(func_ea)

			# Compute metric and store it in the dictionary.
			metric = proc(func_ea)
			metric_dict[func_ea] = (func_name, metric)

			# Keep track of statistical values along the way.
			sum_of_metrics += metric
			min_metric = min(min_metric, metric)
			max_metric = max(max_metric, metric)

		# Get next segment ea.
		seg_ea = idc.get_next_seg(seg_ea)

	# Sort the metric dictionary by highest metric and return this list.
	return (sorted(metric_dict.items(), key=lambda item: item[1][1], reverse=True), min_metric, max_metric, sum_of_metrics)

# The callback executed to compute cyclomatic complexity.
def cyclomatic_complexity():
	# Compute the cyclomatic complexity over all functions in the database and return a sorted list of results.
	results = iterate_functions_and_track_statistics(func_cyclomatic_complexity)

	# Get 95th percentile of result data.
	num = get_95th_percentile(results)

	# Print the results.
	print("Total number of functions: %i. Lowest metric: %f, highest metric: %f." % (len(results[0]), results[1], results[2]))
	print("Top 5%% of functions with highest cyclomatic complexity")
	for i in range(num):
		entry = results[0][i]
		print("Function: 0x%X (%s) has cyclomatic complexity: %f" % (entry[0], entry[1][0], entry[1][1]))
	print("Highest 5%% covers %i out of %i functions." % (num, len(results[0])))

# The callback executed to compute large basic blocks.
def large_basic_blocks():
	# Compute the large basic blocks score over all functions in the database and return a sorted list of results.
	results = iterate_functions_and_track_statistics(func_large_basic_blocks)

	# Get 95th percentile of result data.
	num = get_95th_percentile(results)

	# Print the results.
	print("Total number of functions: %i. Lowest metric: %f, highest metric: %f." % (len(results[0]), results[1], results[2]))
	print("Top 5%% of functions with largest basic blocks.")
	for i in range(num):
		entry = results[0][i]
		print("Function: 0x%X (%s) has large basic block score: %f" % (entry[0], entry[1][0], entry[1][1]))
	print("Highest 5%% covers %i out of %i functions." % (num, len(results[0])))

# Gets overview of most frequently called functions in the database.
def most_frequently_called_functions():
	# Compute the number of cross references to all functions in the database and return a sorted list of results.
	results = iterate_functions_and_track_statistics(func_get_xrefs)

	# Get 95th percentile of result data.
	num = get_95th_percentile(results)

	# Print the results.
	print("Total number of functions: %i. Lowest metric: %f, highest metric: %f." % (len(results[0]), results[1], results[2]))
	print("Top 5%% of most frequently called functions.")
	for i in range(num):
		entry = results[0][i]
		print("Function: 0x%X (%s) has %f calling locations." % (entry[0], entry[1][0], entry[1][1]))
	print("Highest 5%% covers %i out of %i functions." % (num, len(results[0])))

# Computes control flow flattening score for functions.
def control_flow_flattening():
	# Compute the control flow flattening score over all functions in the database and return a sorted list of results.
	results = iterate_functions_and_track_statistics(func_control_flow_flattening)

	# Get 95th percentile of result data.
	num = get_95th_percentile(results)

	# Print the results.
	print("Total number of functions: %i. Lowest metric: %f, highest metric: %f." % (len(results[0]), results[1], results[2]))
	print("Top 5%% of highest control flow flattening scores.")
	for i in range(num):
		entry = results[0][i]
		print("Function: 0x%X (%s) has flattening score: %f." % (entry[0], entry[1][0], entry[1][1]))
	print("Highest 5%% covers %i out of %i functions." % (num, len(results[0])))

# Computes wrong stack frame score for functions.
def wrong_stack_frame():
	# Compute the wrong stack frame score over all functions in the database and return a sorted list of results.
	results = iterate_functions_and_track_statistics(func_wrong_stack_frame)

	# Get 95th percentile of result data.
	num = get_95th_percentile(results)

	# Print the results.
	print("Total number of functions: %i. Lowest metric: %f, highest metric: %f." % (len(results[0]), results[1], results[2]))
	print("Top 5%% of highest wrong stack frame scores.")
	for i in range(num):
		entry = results[0][i]
		print("Function: 0x%X (%s) has wrong stack frame score: %f." % (entry[0], entry[1][0], entry[1][1]))
	print("Highest 5%% covers %i out of %i functions." % (num, len(results[0])))

# Define the action_handler_t object that fires the callback function when each action is activated.
class ActionHandler(idaapi.action_handler_t):
	def __init__(self, callback):
		idaapi.action_handler_t.__init__(self)
		self.callback = callback

	def activate(self, ctx):
		self.callback()
		return 1

	def update(self, ctx):
		return idaapi.AST_ENABLE_ALWAYS

# Registers actions to IDA Pro.
def register_actions():
	actions = [
		{
			'id': 'heuristics:large_basic_blocks:',
			'name': 'Large Basic Blocks',
			'hotkey': 'Ctrl+Alt+B',
			'comment': 'Shows functions with large basic blocks',
			'callback': large_basic_blocks,
			'menu_location': 'Edit/Heuristics/Large Basic Blocks'
		},
		{
			'id': 'heuristics:cyclomatic_complexity',
			'name': 'Cyclomatic Complexity',
			'hotkey': 'Ctrl+Alt+C',
			'comment': 'Shows functions with top cyclomatic complexity',
			'callback': cyclomatic_complexity,
			'menu_location': 'Edit/Heuristics/Cyclomatic Complexity'
		},
		{
			'id' : 'heuristics:frequently_called_funcs',
			'name' : 'Frequenly Called Functions',
			'hotkey' : 'Ctrl+Alt+D',
			'comment' : 'Shows which functions are most frequently called',
			'callback' : most_frequently_called_functions,
			'menu_location' : 'Edit/Heuristics/Frequently Called Functions'
		},
		{
			'id' : 'heuristics:control_flow_flattening',
			'name' : 'Control Flow Flattening',
			'hotkey' : 'Ctrl+Alt+E',
			'comment' : 'Identifies functions with a high level of control flow flattening',
			'callback' : control_flow_flattening,
			'menu_location' : 'Edit/Heuristics/Control Flow Flattening'
		},
		{
			'id' : 'heuristics:wrong_stack_frame',
			'name' :' Wrong Stack Frame',
			'hotkey' : 'Ctrl+Alt+F',
			'comment' : 'Identifies functions with fake stack variables',
			'callback' : wrong_stack_frame,
			'menu_location' : 'Edit/Heuristics/Wrong Stack Frame'
		}
	]

	# Register the specified actions.
	for action in actions:
		if not idaapi.register_action(idaapi.action_desc_t(
			action['id'], action['name'],
			ActionHandler(action['callback']),
			action['hotkey'], action['comment'])):
				print('Failed to register ' + action['id'])

		# Attach registered action to menu bar.
		if not idaapi.attach_action_to_menu(action['menu_location'], action['id'], 0):
			print('Failed to attach to menu '+ action['id'])

class HeuristicsPlugin(idaapi.plugin_t):
	flags = idaapi.PLUGIN_HIDE
	comment = "Implements heuristics for obfuscated code by Tim Blazytko (from REcon)"
	help = "Do you even reverse bro?"
	wanted_name = "Heuristics"
	wanted_hotkey = ''

	def get_user_directory(self):
		user_dir = ida_diskio.get_user_idadir()
		plug_dir = os.path.join(user_dir, "plugins")
		res_dir = os.path.join(plug_dir, "heuristics")
		if not os.path.exists(res_dir):
			os.makedirs(res_dir, 0o755)
		return res_dir

	def init(self):
		global p_initialized

		# Register popup menu handlers.
		register_actions()

		# Set initialized flag to true.
		if p_initialized is False:
			p_initialized = True

		# Get user directory, so we can place files there if needed.
		self.user_directory = self.get_user_directory()

		# Print welcome message with some useful information.
		print("=" * 80)
		print("= Heuristics plugin v%s to detect obfuscation by Gijs Rijnders (evolution536)" % VERSION)
		print("= Implements heuristics as described by Tim Blazytko (REcon)")
		print("= !!! Please wait for auto-analysis to finish before running the script !!!")
		print("=" * 80)

		# Keep the plugin loaded, it might be called from the menu later.
		return idaapi.PLUGIN_KEEP

	def run(self, arg):
		return

	def term(self):
		pass

def PLUGIN_ENTRY():
	return HeuristicsPlugin()
