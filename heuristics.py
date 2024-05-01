import os
import idc
import idaapi
import ida_diskio
import idautils

# Global definitions.
VERSION = "1.0"

# Set initialized flag to false to begin with.
p_initialized = False

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

# The callback executed to compute cyclomatic complexity.
def cyclomatic_complexity():
	return

# The callback executed to compute large basic blocks.
def large_basic_blocks():
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
			# Get function name and object pointer.
			func_name = idc.get_func_name(func_ea)
			func_ptr = idaapi.get_func(func_ea)

			# Get flow chart of the function containing all basic blocks.
			# https://moritzraabe.de/2017/01/15/ida-pro-anti-disassembly-basic-blocks-and-idapython/
			flowchart = idaapi.FlowChart(func_ptr)

			# Get number of instructions inside the function.
			insn_count = count_function_instructions(func_ea)

			# Compute number of instructions divided by the number of basic blocks.
			metric = insn_count / max(1, flowchart.size)
			metric_dict[func_ea] = (func_name, metric)

			# Keep track of statistical values along the way.
			sum_of_metrics += metric
			min_metric = min(min_metric, metric)
			max_metric = max(max_metric, metric)

		# Get next segment ea.
		seg_ea = idc.get_next_seg(seg_ea)

	# Sort the metric dictionary by highest metric.
	sorted_metric_dict = sorted(metric_dict.items(), key=lambda item: item[1][1], reverse=True)
	if len(sorted_metric_dict) > 0:
		# Get first 80 percent by the Pareto principle.
		threshold = metric * 0.8
		slider = 0
		num = 0
		while slider <= threshold:
			num += 1
			slider += sorted_metric_dict[num][1][1]

		# Print the results of the first 80% of largest basic blocks.
		print("Total number of functions: %i. Lowest metric: %f, highest metric: %f." % (len(sorted_metric_dict), min_metric, max_metric))
		print("Top 80% of functions with largest basic blocks.")
		for i in range(num):
			entry = sorted_metric_dict[i]
			print("Function: 0x%X (%s) has large basic block score: %f" % (entry[0], entry[1][0], entry[1][1]))

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
			'hotkey': 'Ctrl+Alt+F',
			'comment': 'Shows functions with large basic blocks',
			'callback': large_basic_blocks,
			'menu_location': 'Edit/Heuristics/Large Basic Blocks'
		},
		{
			'id': 'heuristics:cyclomatic_complexity',
			'name': 'Cyclomatic Complexity',
			'hotkey': 'Ctrl+Alt+E',
			'comment': 'Shows functions with top cyclomatic complexity',
			'callback': cyclomatic_complexity,
			'menu_location': 'Edit/Heuristics/Cyclomatic Complexity'
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
