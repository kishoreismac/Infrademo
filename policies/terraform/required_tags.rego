package terraform.tags

required_tags := {"env", "owner"}

deny[msg] {
  module := input.values.root_module
  resource := module.resources[_]

  tags := resource.values.tags
  missing := required_tags - {k | tags[k]}

  count(missing) > 0

  msg := sprintf(
    "Resource '%s' (%s) is missing required tags: %v",
    [resource.name, resource.type, missing]
  )
}
