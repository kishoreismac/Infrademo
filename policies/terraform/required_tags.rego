package terraform.tags

required_tags := {"env", "owner"}

# ---------- ROOT MODULE ----------
deny contains msg if {
  resource := input.values.root_module.resources[_]
  missing := missing_tags(resource)
  count(missing) > 0
  msg := format_msg(resource, missing)
}

# ---------- CHILD MODULES ----------
deny contains msg if {
  module := input.values.root_module.child_modules[_]
  resource := module.resources[_]
  missing := missing_tags(resource)
  count(missing) > 0
  msg := format_msg(resource, missing)
}

# ---------- HELPERS ----------
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
