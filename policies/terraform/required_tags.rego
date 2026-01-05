package main

required_tags := {"env", "owner"}

########################################
# Entry point
########################################
deny contains msg if {
  resource := all_resources[_]
  missing := missing_tags(resource)
  count(missing) > 0
  msg := format_msg(resource, missing)
}

########################################
# Recursive resource discovery
########################################
all_resources contains resource if {
  walk_module(input.values.root_module, resource)
}

walk_module(module, resource) if {
  resource := module.resources[_]
}

walk_module(module, resource) if {
  child := module.child_modules[_]
  walk_module(child, resource)
}

########################################
# Helpers
########################################
missing_tags(resource) = missing if {
  tags := resource.values.tags
  missing := required_tags - {k | tags[k] != null}
}

format_msg(resource, missing) = msg if {
  msg := sprintf(
    "Resource '%s' (%s) is missing required tags: %v",
    [resource.name, resource.type, missing]
  )
}
