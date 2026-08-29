import os

import lit.formats

config.name = "kagura"
# The internal shell, not the external one: lit 23 removes `execute_external`,
# and every RUN line here is plain `%opt ... | %FileCheck ...` that the internal
# shell handles.
config.test_format = lit.formats.ShTest(execute_external=False)
config.suffixes = [".ll"]

# The .ll files live in the source tree; %t and the Output/ scratch dirs are
# written under the build tree.  Both roots are injected by lit.site.cfg.py,
# which CMake generates — running lit against this file directly is not
# supported (there would be no `opt` / plugin path to substitute).
config.test_source_root = config.kagura_src_root
config.test_exec_root = config.kagura_obj_root

config.substitutions.append(("%kagura_plugin", config.kagura_plugin))
config.substitutions.append(("%FileCheck", config.filecheck))
# Registered last so it cannot shadow the longer names above: lit applies
# substitutions in order, and "%opt" is a prefix of nothing here, but keeping
# the specific-before-general ordering makes future additions safe.
config.substitutions.append(("%opt", config.opt))
